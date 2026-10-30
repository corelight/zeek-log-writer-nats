#pragma once

#include "Connection.h"
#include "NATS.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

/**
 * A log writer using the orbit.c jetstream-extra fast_publish.h
 * functionality to do fast batched publishing to NATS>
 */
class NATSFastPublishWriter : public NATSWriter {
public:
    explicit NATSFastPublishWriter(WriterFrontend* frontend);

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSFastPublishWriter(frontend); }

protected:
    bool DoWrites(int num_fields, const threading::Field* const* fields,
                  std::span<zeek::logging::detail::LogRecord> record) override;

    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override {
        return false;
    }

    bool DoHeartbeat(double network_time, double current_time) override;

    bool DoFinish(double network_time) override;

private:
    FastPublishBatchPolicy batch_policy;
    FastPublisherPtr fast_publisher;
    FastPublisherOptions opts;

    std::vector<zeek::threading::Value*> valps;
    std::vector<std::span<const char>> spans;
    std::vector<zeek::ODesc> descs;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
