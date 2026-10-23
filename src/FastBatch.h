#pragma once

#ifdef HAVE_ORBIT_FAST_PUBLISH

#include <fast_publish.h>
#include <nats/nats.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

class Connection;

/**
 * Outcome of messages that became known during a FastBatch call.
 *
 * The messages may have been published by any writer sharing the batch,
 * the caller accounts for them.
 */
struct FastBatchOutcome {
    // Confirmed by flow acks or the commit ack.
    uint64_t acked = 0;
    // Gaps and per-message errors reported by the server.
    uint64_t failed = 0;
    // In flight when a batch ended, outcome unknown.
    uint64_t unknown = 0;
    // Reason for unknown messages.
    natsStatus reason = NATS_OK;
    // Set by Add() if no batch could be started.
    bool not_started = false;
    // Error text for a failed Add().
    std::string error;
};

/**
 * A fast-ingest (ADR-50) batch shared by all writers of a connection that
 * publish to the same stream.
 *
 * The server divides its flow budget (500 messages per flow ack) across
 * the concurrent batches of a stream. One batch per connection and stream
 * rather than one per writer keeps the full budget. A server-side batch
 * belongs to a single stream, so writers of different streams can't share.
 *
 * The batch stays open across writes and is only committed on flush, when
 * idle, or by the last writer finishing. A batch ended by the server is
 * restarted on the next write.
 */
class FastBatch {
public:
    FastBatch(Connection* conn, const jsFastPublisherOptions& opts, int64_t idle_timeout_ms);
    ~FastBatch();

    // Register a writer. Release() returns true for the last one,
    // which should Commit().
    void Acquire();
    bool Release();

    // Publish messages in order under a single lock acquisition, starting
    // a batch if needed. Blocks while the window of outstanding flow acks
    // is full. Stops at the first failure; published is set to the number
    // of messages published before it.
    natsStatus AddMany(const char* subject, const std::vector<std::string>& msgs, size_t* published,
                       FastBatchOutcome* out);

    // Commit the current batch, if any, waiting up to timeout_ms for the commit ack.
    void Commit(int64_t timeout_ms, FastBatchOutcome* out);

    // Error callback, runs on the ack-handling thread.
    void OnError(natsStatus err, const char* text);

private:
    natsStatus AddLocked(const char* subject, const char* data, int data_len, FastBatchOutcome* out);
    bool StartLocked();
    void EndLocked(bool commit, int64_t timeout_ms, FastBatchOutcome* out);

    Connection* conn;
    jsFastPublisherOptions opts;
    int64_t idle_timeout_ms;

    std::mutex mtx;
    int writers = 0;
    jsFastPublishCtx* ctx = nullptr;
    // Messages published in the current batch.
    uint64_t sent = 0;
    // Highest batch sequence accounted for as acknowledged.
    uint64_t acked = 0;
    int64_t last_publish_ms = 0;

    // Messages failed via the error handler, not yet accounted for.
    std::atomic<uint64_t> async_failed{0};
    // Last batch level error reported via the error handler.
    std::mutex error_mtx;
    std::string batch_error;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail

#endif
