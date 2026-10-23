#pragma once

#include <nats/nats.h>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "zeek/Desc.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/threading/formatters/JSON.h"

#include "Connection.h"
#include "FastBatch.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

struct NATSWriterStats {
    std::atomic<zeek_uint_t> dropped_writes = 0;
    std::atomic<zeek_uint_t> publish_errors = 0;
    std::atomic<zeek_uint_t> publish_acks = 0;
    std::atomic<zeek_uint_t> publish_timeouts = 0;
    // Pending publishes that have neither been acked,
    // timed out, or otherwise failed. May go negative,
    // but that's probably a bug. This value is exposed
    // per writer as metric.
    std::atomic<zeek_int_t> pending = 0;
};

class NATSWriter : public WriterBackend {
public:
    explicit NATSWriter(WriterFrontend* frontend);
    ~NATSWriter() override;

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSWriter(frontend); }

    // Callback for message acknowledgements.
    void PublishAck(const char* stream, uint64_t sequence, const char* domain, bool duplicate);

    // Callback for message delivery errors. n is the number of
    // messages affected by the error.
    void PublishError(natsStatus err, int js_err, const char* text, zeek_uint_t n = 1);

    // Drop a write. That is something the log writer decided
    // to actively drop, rather than hit libnats limits.
    void DropWrite(natsStatus err, const char* text);

    void IncrementPending() { ++writer_stats.pending; }
    void DecrementPending() { --writer_stats.pending; }

    // Return true if this write should be dropped to prevent stalling.
    bool MayStall() const {
        if ( publish_async_no_stall && publish_async_max_pending > 0 )
            return writer_stats.pending >= publish_async_max_pending;

        return false;
    };

protected:
    bool DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) override;
    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override;
    bool DoSetBuf(bool enabled) override { return true; }
    bool DoRotate(const char* rotated_path, double open, double close, bool terminating) override;
    bool DoFlush(double network_time) override;
    bool DoFinish(double network_time) override;
    bool DoHeartbeat(double network_time, double current_time) override;

    // Try connect and setup the stream.
    bool Connect();

    zeek::threading::formatter::JSON& Formatter() { return *formatter; }

    const std::string& PublishSubject() const { return publish_subject; }

    zeek::ODesc& Desc() { return desc; }

    std::shared_ptr<Connection>& Conn() { return conn; }

#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Buffer a single message for the connection's shared fast-ingest
    // batch, publishing the buffer once fast_ingest_writer_batch is reached.
    void FastIngestWrite(const char* data, int data_len);

    // Publish all buffered messages to the shared batch at once.
    void FastIngestPublishBuffered();

    // Account for the outcome reported by the shared batch. Messages with
    // unknown outcome are publish errors, or dropped writes if at_finish
    // is true.
    void FastIngestAccount(const FastBatchOutcome& out, bool at_finish);
#endif

private:
    std::shared_ptr<Connection> conn = nullptr;
    jsCtx* js = nullptr;

    enum class PublishMode {
        ASYNC,
        FAST_INGEST,
    };
    PublishMode mode = PublishMode::ASYNC;
    std::string publish_mode;

#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Shared by all writers of the connection. Outcomes are accounted
    // to whichever writer observes them, so per-writer acks and errors
    // are approximate while totals are exact.
    std::shared_ptr<FastBatch> fast_batch;
#endif

    std::string url;
    std::string conn_sharing_policy;
    std::string stream_name_template;
    std::string stream_subject_template;
    std::string stream_name;
    std::string publish_subject_template;
    std::string publish_subject;
    std::string stream_subject;
    std::vector<const char*> stream_subjects;
    zeek_uint_t stream_storage;
    int64_t connection_timeout_ms;
    int64_t ping_interval_ms;
    int64_t reconnect_wait_ms;
    int64_t jitter_ms;
    int64_t jitter_tls_ms;

    std::unique_ptr<zeek::threading::formatter::JSON> formatter;
    zeek::ODesc desc;
    bool include_unset_fields;
    bool create_stream;
    std::string json_timestamps;
    std::string path_escape_policy;

    NATSWriterStats writer_stats;
    zeek_uint_t publish_error_log;
    zeek_uint_t dropped_writes_log;
    int64_t publish_async_max_pending;
    int64_t publish_async_max_wait_ms;
    int64_t publish_async_stall_wait_ms;
    bool publish_async_no_stall;
    int64_t publish_async_complete_max_wait_ms;
    zeek_uint_t fast_ingest_flow;
    zeek_uint_t fast_ingest_max_outstanding_acks;
    int64_t fast_ingest_ack_timeout_ms;
    bool fast_ingest_continue_on_gap;
    int64_t fast_ingest_idle_timeout_ms;
    zeek_uint_t fast_ingest_writer_batch;
#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Formatted messages not yet published to the shared batch.
    std::vector<std::string> fast_buffered;
#endif

    zeek::telemetry::CounterPtr dropped_writes_total;
    zeek::telemetry::CounterPtr publish_errors_total;
    zeek::telemetry::CounterPtr publish_timeouts_total;
    zeek::telemetry::CounterPtr publish_acks_total;
    zeek::telemetry::GaugePtr publishes_pending;
};
} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
