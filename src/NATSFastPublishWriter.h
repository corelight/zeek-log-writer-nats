#pragma once

#include <fast_publish.h>

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

    // Callback
    void ErrorHandler(natsStatus status, const char* description);

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSFastPublishWriter(frontend); }

protected:
    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override;

    bool DoHeartbeat(double network_time, double current_time) override;

    bool DoFinish(double network_time) override;

private:
    // Helper to commit a batch on heartbeat and at shutdown.
    bool CommitBatch();

    jsFastPublishCtx* fp_ctx = nullptr;

    size_t batch_size = 0;
    size_t max_batch_size = 1000;
    int64_t commit_timeout_ms = 5000;
    bool continue_on_gap = true;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
