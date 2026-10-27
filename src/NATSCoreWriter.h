#pragma once

#include "NATS.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

/**
 * A log writer that uses pure Core NATS to publish for DoWrite() rather
 * than the JetStream API for improved throughput.
 */
class NATSCoreWriter : public NATSWriter {
public:
    explicit NATSCoreWriter(WriterFrontend* frontend);

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSCoreWriter(frontend); }

protected:
    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override;

    bool DoFinish(double network_time) override;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
