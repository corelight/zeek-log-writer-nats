#pragma once

#include <nats/nats.h>
#include <memory>
#include <vector>

#include "zeek/Desc.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/threading/formatters/JSON.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_NATS::detail {

struct NATSWriterStats {
    zeek_uint_t dropped_writes = 0;
    zeek_uint_t publish_errors = 0;
};

class NATSWriter : public WriterBackend {
public:
    explicit NATSWriter(WriterFrontend* frontend);
    ~NATSWriter() override;

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSWriter(frontend); }

    void PublishError(int code, const char* text);

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

private:
    natsConnection* conn = nullptr;
    natsOptions* opts = nullptr;
    jsCtx* js = nullptr;
    jsOptions jsOpts;
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

    NATSWriterStats writer_stats;
    zeek_uint_t publish_error_log;
    zeek_uint_t dropped_writes_log;
    int64_t publish_async_max_pending;
    int64_t publish_async_stall_wait_ms;
    int64_t publish_async_complete_max_wait_ms;
};
} // namespace zeek::plugin::Zeek_NATS::detail
