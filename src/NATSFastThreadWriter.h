#pragma once

#include <memory>
#include <string>
#include <vector>

#include "Connection.h"
#include "FastBatch.h"
#include "NATS.h"

using namespace zeek::logging;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

/**
 * A log writer publishing fast-ingest batches (ADR-50) from a separate
 * publisher thread.
 *
 * All writers of a connection publishing to the same stream share one
 * FastBatch. Writers buffer formatted messages and queue them for the
 * batch's publisher thread, so only that thread blocks on flow control.
 */
class NATSFastThreadWriter : public NATSWriter {
public:
    explicit NATSFastThreadWriter(WriterFrontend* frontend);
    ~NATSFastThreadWriter() override;

    static WriterBackend* Instantiate(WriterFrontend* frontend) { return new NATSFastThreadWriter(frontend); }

protected:
    bool DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) override;
    bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) override;
    bool DoFlush(double network_time) override;
    bool DoFinish(double network_time) override;
    bool DoHeartbeat(double network_time, double current_time) override;

    bool StreamAllowBatched() const override { return true; }

private:
    // Buffer a single message for the shared batch, queueing the buffer
    // once writer_batch is reached.
    void BufferWrite(const char* data, int data_len);

    // Queue all buffered messages for the shared batch at once.
    void PublishBuffered();

    FastPublisherOptions opts;
    // Validated in DoInit() before they're set in opts.
    zeek_uint_t flow;
    zeek_uint_t max_outstanding_acks;
    zeek_uint_t writer_batch;
    zeek_uint_t queue_size;
    int64_t stall_wait_ms;

    // Shared by all writers of the connection publishing to the stream.
    std::shared_ptr<FastBatch> fast_batch;
    // This writer as seen by the batch's publisher thread.
    std::shared_ptr<FastBatchWriter> fast_writer;
    // Formatted messages not yet queued for the shared batch.
    std::vector<std::string> buffered;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
