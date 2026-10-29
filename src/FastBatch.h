#pragma once

#include <fast_publish.h>
#include <nats/nats.h>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Connection.h"
#include "WriterStats.h"

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

/**
 * Configuration of a shared fast-ingest batch, taken from the first
 * writer acquiring it.
 */
struct FastBatchConfig {
    // Stream name, for log messages.
    std::string stream;
    // Flow control, commit timeout (also bounding the wait for a flow
    // ack), idle timeout and continue_on_gap. max_batch_size isn't used:
    // the batch stays open until it's committed.
    FastPublisherOptions publisher;
    // Bytes of queued messages before writers stall or drop.
    uint64_t queue_bytes = 64 * 1024 * 1024;
    // Drop writes when the queue is still full after stall_wait_ms,
    // otherwise wait for space.
    bool no_stall = true;
    int64_t stall_wait_ms = 50;
    // Log the first error and every publish_error_log-th one, 0 to disable.
    uint64_t publish_error_log = 1;
};

/**
 * A log writer publishing through a shared batch.
 */
struct FastBatchWriter {
    // Log path, for log messages.
    std::string path;
    std::string subject;
    std::shared_ptr<NATSWriterStats> stats;
    // Set by FastBatch::Finish(), guarded by the batch's mutex. Messages
    // of a finished writer are no longer published or accounted.
    bool finished = false;
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
 * Writers queue formatted messages, a single publisher thread publishes
 * them in order. Only the publisher thread blocks on flow control, writers
 * wait at most stall_wait_ms for queue space (or indefinitely without
 * no_stall). The queue is bounded by queue_bytes, so a stalled server
 * can't grow memory without bound.
 *
 * The publisher thread tracks which writer published every message of the
 * batch and accounts flow acks, gaps, errors and messages of unknown
 * outcome (timeouts) exactly to that writer's stats.
 *
 * The batch stays open and is committed on Flush(), when idle, and when
 * the last writer is released. A batch ended by an error or timeout is
 * committed if possible and restarted for the next message.
 */
class FastBatch {
public:
    FastBatch(std::shared_ptr<Connection> conn, FastBatchConfig cfg);
    ~FastBatch();

    FastBatch(const FastBatch&) = delete;
    FastBatch& operator=(const FastBatch&) = delete;

    const FastBatchConfig& Config() const { return cfg; }

    // Register a writer.
    void Acquire();

    // Unregister a writer. The last one stops the publisher thread, which
    // commits the batch waiting at most timeout_ms. Messages still queued
    // then are counted as dropped writes.
    void Release(int64_t timeout_ms);

    // Queue messages of writer w for publishing. The caller counts them as
    // pending of w beforehand. Returns the number of messages dropped
    // because the queue stayed full for stall_wait_ms with no_stall, or
    // because the batch is stopping. Those are left for the caller to
    // account.
    size_t Enqueue(const std::shared_ptr<FastBatchWriter>& w, std::vector<std::string>&& msgs);

    // Commit the batch once everything queued so far is published. Waits up
    // to timeout_ms for the commit and returns false if that timed out.
    bool Flush(int64_t timeout_ms);

    // Wait up to timeout_ms until all messages of w are accounted. Messages
    // still pending then are counted as dropped writes of w and ignored
    // afterwards. Returns their number.
    uint64_t Finish(const std::shared_ptr<FastBatchWriter>& w, int64_t timeout_ms);

    // Error callback, runs on the ack-handling thread.
    void OnError(natsStatus err, const char* text);

private:
    // Messages of a writer, or a flush marker without writer.
    struct Chunk {
        std::shared_ptr<FastBatchWriter> writer;
        std::vector<std::string> msgs;
        uint64_t bytes = 0;
        uint64_t flush_id = 0;
    };

    // Consecutive batch sequences published by one writer.
    struct InFlight {
        uint64_t first;
        uint64_t last;
        std::shared_ptr<FastBatchWriter> writer;
    };

    // Publisher thread.
    void Run();
    void Publish(Chunk& chunk);
    bool StartBatch();
    // End the current batch, committing it if commit is true. Messages
    // neither confirmed nor failed are accounted as timeouts (outcome
    // unknown) if reason is NATS_TIMEOUT, a commit timed out or
    // outcome_unknown is set, otherwise as errors.
    void EndBatch(bool commit, int64_t timeout_ms, natsStatus reason, bool outcome_unknown = false);
    // End the batch if the connection reconnected since it started. The
    // server may have lost it, e.g. when it restarted.
    void EndBatchIfReconnected();
    void Track(const std::shared_ptr<FastBatchWriter>& w, uint64_t seq);
    // Account in-flight messages up to batch sequence seq as acked, minus
    // gaps reported by the server. Requires mtx.
    void ResolveLocked(uint64_t seq);
    // Count errors and timeouts of w and log them. Requires mtx.
    void AccountErrors(FastBatchWriter& w, uint64_t errors, uint64_t timeouts, const char* reason);

    std::shared_ptr<Connection> conn;
    FastBatchConfig cfg;

    std::mutex mtx;
    // Publisher thread waits for work.
    std::condition_variable work_cv;
    // Writers wait for queue space.
    std::condition_variable space_cv;
    // Flush() and Finish() wait for progress.
    std::condition_variable done_cv;
    std::deque<Chunk> queue;
    uint64_t queued_bytes = 0;
    uint64_t flush_requested = 0;
    uint64_t flush_completed = 0;
    int writers = 0;
    bool stopping = false;
    int64_t stop_timeout_ms = 0;
    std::thread thread;

    // Publisher thread only.
    jsFastPublishCtx* ctx = nullptr;
    // Batch sequence of the last message published.
    uint64_t sent = 0;
    // Highest batch sequence confirmed by a flow ack.
    uint64_t acked = 0;
    int64_t last_publish_ms = 0;
    // Connection epoch when the batch started.
    uint64_t batch_epoch = 0;
    std::deque<InFlight> inflight;

    // Ranges of batch sequences reported lost or failed by the server,
    // filled by the ack-handling thread.
    std::mutex errors_mtx;
    std::vector<std::pair<uint64_t, uint64_t>> failed;
    std::string batch_error;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
