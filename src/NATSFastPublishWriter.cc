#include "NATSFastPublishWriter.h"

#include <nats/nats.h>
#include <nats/status.h>

#include "Connection.h"
#include "NATS.h"
#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSFastPublishWriter::NATSFastPublishWriter(WriterFrontend* frontend)
    : NATSWriter(frontend, /*send_heartbeats=*/true) {
    constexpr uint64_t uint16max = std::numeric_limits<uint16_t>::max();

    auto tmp_flow = zeek::id::find_val<zeek::StringVal>("LogNATS::fast_publish_flow")->AsCount();

    if ( tmp_flow > uint16max ) {
        eprintf("flow value too large %" PRIu64, tmp_flow);
        tmp_flow = uint16max;
    }

    opts.flow = tmp_flow;

    auto tmp_max_outstanding_acks =
        zeek::id::find_val<zeek::StringVal>("LogNATS::fast_publish_max_outstanding_acks")->AsCount();

    if ( tmp_max_outstanding_acks > uint16max ) {
        eprintf("max_outstanding_acks too large: %" PRIu64, tmp_max_outstanding_acks);
        tmp_max_outstanding_acks = uint16max;
    }

    opts.max_outstanding_acks = tmp_max_outstanding_acks;

    opts.commit_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_commit_timeout")->AsInterval() * 1000);
    opts.ack_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_ack_timeout")->AsInterval() * 1000);

    auto tmp_pool_size = zeek::id::find_val("LogNATS::fast_publish_pool_size")->AsCount();

    if ( tmp_pool_size > uint16max ) {
        eprintf("pool_size value too large %" PRIu64, tmp_flow);
        tmp_pool_size = uint16max;
    }

    opts.pool_size = tmp_pool_size;

    auto batch_policy_str = zeek::obj_desc_short(zeek::id::find_val("LogNATS::fast_publish_batch_policy").get());

    if ( batch_policy_str == "LogNATS::BATCH_EXCLUSIVE" )
        batch_policy = FastPublishBatchPolicy::EXCLUSIVE;
    else if ( batch_policy_str == "LogNATS::BATCH_SHARED" )
        batch_policy = FastPublishBatchPolicy::SHARED;
    else if ( batch_policy_str == "LogNATS::BATCH_POOLED" )
        batch_policy = FastPublishBatchPolicy::POOLED;
    else {
        eprintf("Invalid fast_publish_batch_policy: %s", batch_policy_str.c_str());
        abort(); // This really should not happen...
    }

    debug("fast_publish: path=%s batch_policy=%s flow=%" PRIu16 " max_outstanding_acks=%" PRIu16
          " commit_timeout_ms=%" PRId64,
          Info().path, batch_policy_str.c_str(), opts.flow, opts.max_outstanding_acks, opts.commit_timeout_ms);
}


bool NATSFastPublishWriter::DoWrites(int num_fields, const threading::Field* const* fields,
                                     std::span<zeek::logging::detail::LogRecord> records) {
    //
    // We should stall here unless we're being shutdown.
    //
    if ( ! Conn()->IsConnected() ) {
        // Add a DropWrites() helper?
        writer_stats->dropped_writes += (records.size() - 1);
        DropWrite(NATS_NOT_YET_CONNECTED, "not yet connected");
        return true;
    }

    if ( ! fast_publisher )
        fast_publisher = Conn()->GetFastPublisher(batch_policy, opts);

    // debug("Got a batch of %zu", records.size());

    if ( records.size() > descs.size() ) {
        // The ODesc destructors free their buffer when
        // reallocation happens. Prevent this here.
        descs.clear();
        descs.resize(records.size());
    }

    spans.resize(records.size());
    valps.resize(num_fields);

    for ( size_t i = 0; i < records.size(); i++ ) {
        auto record = records[i];

        for ( size_t j = 0; j < record.size(); j++ )
            valps[j] = &record[j];

        if ( ! Format(descs[i], num_fields, fields, valps.data()) ) {
            // XXX: Drop all of the writes? We just lost a whole batch.
            //
            // This should just never ever happen!
            DropWrite(NATS_ERR, "FormatMessage() failed");
            return true;
        }

        spans[i] = std::span{descs[i].Description(), descs[i].Size()};
    }


    // This is the completion callback for the fast publisher. When all
    // messages provided to DoWrites() have completes (or failed), this
    // callback runs to update the writers stats.
    FastPublisher::CompletionCallback ccb = [stats = writer_stats](FastPublisher::CompletionInfo info) {
        stats->publish_acks += info.acked;
        stats->dropped_writes += info.dropped;
        stats->publish_errors += info.failed;
    };

    const char* subject = PublishSubject().c_str();
    if ( auto [ok, status, error] = fast_publisher->AddMsgs(subject, spans, std::move(ccb)); ! ok ) {
        // Failure was handled via the CompletionCallback already,
        // so not sure we need to do anything here? Maybe log once
        // in a while if something fails?
    }

    return true;
}


bool NATSFastPublishWriter::DoHeartbeat(double network_time, double current_time) {
    if ( fast_publisher ) {
        // debug("%s: DoHeartbeat batch_size=%zu idle=%d", Info().path, fast_publisher->BatchSize(),
        //              fast_publisher->IsIdle());
        if ( fast_publisher->IsIdle() )
            fast_publisher->CloseBatch(/*commit=*/true);
    }

    return true;
}


bool NATSFastPublishWriter::DoFinish(double network_time) {
    debug("DoFinish");

    if ( fast_publisher ) {
        Conn()->PutFastPublisher(std::move(fast_publisher));
        fast_publisher.reset(); // implied, but be explicit.
    }

    return true;
}
