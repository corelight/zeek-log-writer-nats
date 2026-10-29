#include "NATSFastThreadWriter.h"

#include <nats/nats.h>
#include <cinttypes>
#include <mutex>

#include "zeek/ID.h"
#include "zeek/Val.h"

#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

namespace {
// nats-server uses at most this many messages per fast-ingest flow ack,
// divided across the concurrent batches of a stream (fastBatchInit() and
// checkFlowControl() in server/jetstream_batching.go).
constexpr zeek_uint_t max_fast_publish_flow = 500;
} // namespace

// Heartbeats queue the buffered writes of a quiet writer.
NATSFastThreadWriter::NATSFastThreadWriter(WriterFrontend* frontend) : NATSWriter(frontend, /*send_heartbeats=*/true) {
    flow = zeek::id::find_val("LogNATS::fast_publish_flow")->AsCount();
    max_outstanding_acks = zeek::id::find_val("LogNATS::fast_publish_max_outstanding_acks")->AsCount();

    // The batch stays open until it's committed.
    opts.max_batch_size = 0;
    opts.commit_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_commit_timeout")->AsInterval() * 1000);
    opts.idle_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_idle_timeout")->AsInterval() * 1000);

    writer_batch = zeek::id::find_val("LogNATS::fast_publish_thread_writer_batch")->AsCount();
    queue_size = zeek::id::find_val("LogNATS::fast_publish_thread_queue_size")->AsCount();
    stall_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_thread_stall_wait")->AsInterval() * 1000);
}

NATSFastThreadWriter::~NATSFastThreadWriter() {
    // Without DoFinish(), e.g. when initialization failed.
    if ( fast_batch )
        fast_batch->Release(opts.commit_timeout_ms);

    fast_batch = nullptr;
}

bool NATSFastThreadWriter::DoInit(const WriterInfo& info, int arg_num_fields,
                                  const threading::Field* const* arg_fields) {
    if ( flow < 1 || flow > UINT16_MAX ) {
        eprintf("Invalid fast_publish_flow %" PRIu64 " (1-%u)", flow, UINT16_MAX);
        return false;
    }

    // The server never acknowledges less often than every 500 messages.
    if ( flow > max_fast_publish_flow ) {
        static std::once_flag warned;
        std::call_once(warned, [this]() {
            eprintf("fast_publish_flow %" PRIu64 " exceeds the server's maximum, using %" PRIu64, flow,
                    max_fast_publish_flow);
        });

        opts.flow = max_fast_publish_flow;
    }
    else
        opts.flow = static_cast<uint16_t>(flow);

    if ( max_outstanding_acks < 1 || max_outstanding_acks > UINT16_MAX ) {
        eprintf("Invalid fast_publish_max_outstanding_acks %" PRIu64 " (1-%u)", max_outstanding_acks, UINT16_MAX);
        return false;
    }

    opts.max_outstanding_acks = static_cast<uint16_t>(max_outstanding_acks);

    if ( opts.commit_timeout_ms <= 0 ) {
        eprintf("Invalid fast_publish_commit_timeout %" PRId64 "ms", opts.commit_timeout_ms);
        return false;
    }

    if ( opts.idle_timeout_ms < 0 ) {
        eprintf("Invalid fast_publish_idle_timeout %" PRId64 "ms", opts.idle_timeout_ms);
        return false;
    }

    if ( writer_batch < 1 ) {
        eprintf("Invalid fast_publish_thread_writer_batch %" PRIu64 " (>= 1)", writer_batch);
        return false;
    }

    if ( queue_size < 1 ) {
        eprintf("Invalid fast_publish_thread_queue_size %" PRIu64 " (>= 1)", queue_size);
        return false;
    }

    if ( stall_wait_ms < 0 ) {
        eprintf("Invalid fast_publish_thread_stall_wait %" PRId64 "ms", stall_wait_ms);
        return false;
    }

    return NATSWriter::DoInit(info, arg_num_fields, arg_fields);
}

bool NATSFastThreadWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    if ( ! Connect() ) {
        DropWrite(NATS_NOT_YET_CONNECTED, "not yet connected in DoWrite()");
        return true;
    }

    if ( ! Format(Desc(), num_fields, fields, vals) ) {
        DropWrite(NATS_ERR, "Format() failed");
        return true;
    }

    BufferWrite(reinterpret_cast<const char*>(Desc().Bytes()), static_cast<int>(Desc().Size()));
    return true;
}

void NATSFastThreadWriter::BufferWrite(const char* data, int data_len) {
    // Publishing while disconnected would stall for fast_publish_commit_timeout
    // waiting on flow acks that can't arrive.
    if ( ! Conn()->IsConnected() ) {
        DropWrite(NATS_CONNECTION_DISCONNECTED, "not connected in DoWrite()");
        return;
    }

    // Buffered writes count as pending, so that at any time every write
    // is acked, failed, timed out, dropped or pending.
    buffered.emplace_back(data, data_len);
    IncrementPending();

    if ( buffered.size() >= writer_batch )
        PublishBuffered();
}

void NATSFastThreadWriter::PublishBuffered() {
    if ( buffered.empty() )
        return;

    if ( ! Conn()->IsConnected() ) {
        Stats()->pending -= static_cast<int64_t>(buffered.size());
        DropWrite(NATS_CONNECTION_DISCONNECTED, "not connected when queueing buffered writes", buffered.size());
        buffered.clear();
        return;
    }

    if ( ! fast_batch ) {
        FastBatchConfig cfg{
            .stream = StreamName(),
            .publisher = opts,
            .queue_bytes = queue_size,
            .no_stall = PublishAsyncNoStall(),
            .stall_wait_ms = stall_wait_ms,
            .publish_error_log = PublishErrorLog(),
        };

        fast_batch = Conn()->AcquireFastBatch(cfg);
        fast_writer = std::make_shared<FastBatchWriter>(FastBatchWriter{
            .path = Info().path,
            .subject = PublishSubject(),
            .stats = Stats(),
        });
    }

    if ( size_t dropped = fast_batch->Enqueue(fast_writer, std::move(buffered)); dropped > 0 ) {
        Stats()->pending -= static_cast<int64_t>(dropped);
        DropWrite(NATS_ERR, "fast-ingest queue full", dropped);
    }

    buffered.clear();
    buffered.reserve(writer_batch);
}

bool NATSFastThreadWriter::DoFlush(double network_time) {
    debug("DoFlush");

    // Commit the shared batch once all writes so far are published, so
    // they're confirmed. Otherwise, the last partial flow window is only
    // acknowledged by later writes. The next write starts a new batch.
    PublishBuffered();

    if ( fast_batch && ! fast_batch->Flush(opts.commit_timeout_ms) )
        debug("DoFlush: fast-ingest commit timed out");

    return true;
}

bool NATSFastThreadWriter::DoFinish(double network_time) {
    debug("DoFinish");

    PublishBuffered();

    if ( fast_batch ) {
        if ( auto n = fast_batch->Finish(fast_writer, PublishAsyncCompleteMaxWaitMs()); n > 0 )
            eprintf("%s: DoFinish: %" PRIu64 " fast-ingest writes not confirmed in time, counted as dropped",
                    Info().path, n);

        // The last writer of the batch commits it and stops its
        // publisher thread.
        fast_batch->Release(PublishAsyncCompleteMaxWaitMs());
        fast_batch = nullptr;
    }

    return true;
}

bool NATSFastThreadWriter::DoHeartbeat(double network_time, double current_time) {
    debug("DoHeartbeat");

    // Bound how long buffered writes of a quiet writer wait.
    PublishBuffered();

    return true;
}
