#pragma once

#include <nats/nats.h>
#include <memory>
#include <vector>

#include "zeek/Desc.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/threading/formatters/JSON.h"

#include "Connection.h"

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

    // Callback for message delivery errors.
    void PublishError(natsStatus err, int js_err, const char* text);

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

private:
    std::shared_ptr<Connection> conn = nullptr;
    jsCtx* js = nullptr;

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

    zeek::telemetry::CounterPtr dropped_writes_total;
    zeek::telemetry::CounterPtr publish_errors_total;
    zeek::telemetry::CounterPtr publish_timeouts_total;
    zeek::telemetry::CounterPtr publish_acks_total;
    zeek::telemetry::GaugePtr publishes_pending;
};
} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
