#pragma once

#include <nats/nats.h>
#include <chrono>
#include <memory>
#include <vector>

#include "zeek/Desc.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/threading/formatters/JSON.h"

#include "SharedClient.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

class NATSWriter : public WriterBackend {
public:
    explicit NATSWriter(WriterFrontend* frontend);
    ~NATSWriter() override;

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSWriter(frontend); }

protected:
    bool DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) override;
    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override;
    bool DoSetBuf(bool enabled) override { return true; }
    bool DoRotate(const char* rotated_path, double open, double close, bool terminating) override;
    bool DoFlush(double network_time) override;
    bool DoFinish(double network_time) override;
    bool DoHeartbeat(double network_time, double current_time) override;

    // Returns the shared JetStream context, connecting and setting up
    // the stream if needed. Returns nullptr if not connected.
    jsCtx* Connect();

    // Counts and logs a write that was dropped.
    void DroppedWrite();

    // Returns true if a publish should be skipped because an earlier one
    // stalled and the server hasn't responded to anything since.
    bool SkipStalledPublish();

private:
    std::shared_ptr<SharedClient> client;
    jsCtx* js = nullptr; // Owned by client.
    bool stream_added = false;

    // Set when a publish timed out waiting for publish_async_max_pending
    // to free up, along with the client's response count at that time.
    bool stalled = false;
    uint64_t stalled_responses = 0;
    std::chrono::steady_clock::time_point last_stalled_publish;
    std::string url;
    std::string stream_name_template;
    std::string stream_subject_template;
    std::string stream_name;
    std::string publish_subject_template;
    std::string publish_subject;
    std::string stream_subject;
    std::vector<const char*> stream_subjects;
    zeek_uint_t stream_storage;


    std::unique_ptr<zeek::threading::formatter::JSON> formatter;
    zeek::ODesc desc;
    bool include_unset_fields;
    bool create_stream;
    std::string json_timestamps;
    std::string path_escape_policy;

    std::shared_ptr<NATSWriterStats> writer_stats;
    zeek_uint_t dropped_writes_log;
    bool share_connection;
    int64_t publish_async_max_pending;
    int64_t publish_async_stall_wait_ms;
    int64_t publish_async_complete_max_wait_ms;

    zeek::telemetry::CounterPtr dropped_writes_total;
    zeek::telemetry::CounterPtr publish_errors_total;
    zeek::telemetry::CounterPtr publish_acks_total;
};
} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
