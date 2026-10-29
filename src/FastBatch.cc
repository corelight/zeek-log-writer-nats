#include "FastBatch.h"

#include <pthread.h>
#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>

#include "Connection.h"
#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

namespace {
void _fastBatchErr(natsStatus status, const char* description, void* closure) {
    static_cast<FastBatch*>(closure)->OnError(status, description);
}

// Rough per-message overhead of a queued std::string on top of its data.
constexpr uint64_t queued_msg_overhead = sizeof(std::string);

// Number of sequences of [first, last] within the given ranges.
uint64_t overlap(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t first, uint64_t last) {
    uint64_t n = 0;
    for ( const auto& [from, to] : ranges ) {
        uint64_t lo = std::max(from, first);
        uint64_t hi = std::min(to, last);
        if ( lo <= hi )
            n += hi - lo + 1;
    }

    return n;
}
} // namespace

FastBatch::FastBatch(std::shared_ptr<Connection> conn, FastBatchConfig cfg)
    : conn(std::move(conn)), cfg(std::move(cfg)) {}

FastBatch::~FastBatch() {
    {
        std::scoped_lock lock{mtx};
        stopping = true;
        stop_timeout_ms = cfg.publisher.commit_timeout_ms;
    }

    work_cv.notify_one();

    if ( thread.joinable() )
        thread.join();
}

void FastBatch::Acquire() {
    std::scoped_lock lock{mtx};
    ++writers;
}

void FastBatch::Release(int64_t timeout_ms) {
    // Joined without holding mtx. Taking it out of thread under mtx keeps
    // Enqueue() and Flush() of a writer acquiring the batch meanwhile from
    // racing on it, and Enqueue() doesn't start a new thread while stopping.
    std::thread publisher;
    {
        std::scoped_lock lock{mtx};
        if ( --writers > 0 )
            return;

        stopping = true;
        stop_timeout_ms = timeout_ms;
        publisher = std::move(thread);
    }

    work_cv.notify_one();
    space_cv.notify_all();

    if ( publisher.joinable() )
        publisher.join();

    // A writer may still acquire the batch again, e.g. for a new log path.
    std::scoped_lock lock{mtx};
    stopping = false;
}

size_t FastBatch::Enqueue(const std::shared_ptr<FastBatchWriter>& w, std::vector<std::string>&& msgs) {
    size_t n = msgs.size();
    if ( n == 0 )
        return 0;

    uint64_t bytes = 0;
    for ( const auto& m : msgs )
        bytes += m.size() + queued_msg_overhead;

    std::unique_lock lock{mtx};

    // An empty queue always takes a chunk, even one larger than queue_bytes.
    auto has_space = [&]() { return stopping || queued_bytes == 0 || queued_bytes + bytes <= cfg.queue_bytes; };

    if ( ! has_space() ) {
        if ( ! cfg.no_stall )
            space_cv.wait(lock, has_space);
        else if ( ! space_cv.wait_for(lock, std::chrono::milliseconds(cfg.stall_wait_ms), has_space) )
            return n;
    }

    if ( stopping )
        return n;

    if ( ! thread.joinable() )
        thread = std::thread([this]() { Run(); });

    queued_bytes += bytes;
    queue.push_back(Chunk{w, std::move(msgs), bytes, 0});
    lock.unlock();

    work_cv.notify_one();
    return 0;
}

bool FastBatch::Flush(int64_t timeout_ms) {
    std::unique_lock lock{mtx};

    // Nothing was queued since the publisher thread last stopped, or it's
    // stopping, which commits anyway.
    if ( ! thread.joinable() )
        return true;

    uint64_t id = ++flush_requested;
    queue.push_back(Chunk{nullptr, {}, 0, id});
    work_cv.notify_one();

    return done_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() { return flush_completed >= id; });
}

uint64_t FastBatch::Finish(const std::shared_ptr<FastBatchWriter>& w, int64_t timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    // Commit, so the last partial flow window is confirmed.
    Flush(timeout_ms);

    std::unique_lock lock{mtx};
    done_cv.wait_until(lock, deadline, [&]() { return w->stats->pending <= 0; });

    w->finished = true;
    int64_t pending = w->stats->pending.exchange(0);
    if ( pending <= 0 )
        return 0;

    w->stats->dropped_writes += pending;
    return static_cast<uint64_t>(pending);
}

void FastBatch::OnError(natsStatus err, const char* text) {
    // Messages [expected_last, current) were lost. A backward gap
    // (current <= expected_last) ends the batch, the commit ack then
    // confirms what was persisted.
    uint64_t expected_last = 0;
    uint64_t current = 0;
    if ( std::sscanf(text, "fast publish gap: expected_last=%" SCNu64 " current=%" SCNu64, &expected_last, &current) ==
         2 ) {
        if ( current > expected_last ) {
            std::scoped_lock lock{errors_mtx};
            failed.emplace_back(expected_last, current - 1);
        }

        return;
    }

    // A single message failed, the batch continues.
    uint64_t seq = 0;
    if ( std::sscanf(text, "fast publish error at sequence %" SCNu64, &seq) == 1 ) {
        std::scoped_lock lock{errors_mtx};
        failed.emplace_back(seq, seq);
        return;
    }

    // Everything else ends the batch.
    debug("FastBatch error: %s", text);
    std::scoped_lock lock{errors_mtx};
    batch_error = text;
}

void FastBatch::Run() {
#ifdef __linux__
    pthread_setname_np(pthread_self(), "zk.nats-fast");
#endif

    std::unique_lock lock{mtx};

    while ( ! stopping ) {
        if ( queue.empty() ) {
            auto has_work = [&]() { return stopping || ! queue.empty(); };

            if ( ! ctx || cfg.publisher.idle_timeout_ms <= 0 ) {
                work_cv.wait(lock, has_work);
                continue;
            }

            // Commit idle batches, the server abandons them after 10
            // seconds without traffic.
            int64_t wait_ms = std::max<int64_t>(1, last_publish_ms + cfg.publisher.idle_timeout_ms - nats_Now());
            if ( ! work_cv.wait_for(lock, std::chrono::milliseconds(wait_ms), has_work) &&
                 nats_Now() - last_publish_ms >= cfg.publisher.idle_timeout_ms ) {
                lock.unlock();
                EndBatchIfReconnected();
                if ( ctx )
                    EndBatch(/*commit=*/true, cfg.publisher.commit_timeout_ms, NATS_OK);
                lock.lock();
            }

            continue;
        }

        Chunk chunk = std::move(queue.front());
        queue.pop_front();
        queued_bytes -= chunk.bytes;
        space_cv.notify_all();
        lock.unlock();

        if ( chunk.writer )
            Publish(chunk);
        else {
            EndBatchIfReconnected();
            if ( ctx )
                EndBatch(/*commit=*/true, cfg.publisher.commit_timeout_ms, NATS_OK);
        }

        lock.lock();

        if ( ! chunk.writer ) {
            flush_completed = std::max(flush_completed, chunk.flush_id);
            done_cv.notify_all();
        }
    }

    // Stopping: drop what's still queued and commit.
    uint64_t dropped = 0;
    for ( auto& chunk : queue ) {
        if ( ! chunk.writer ) {
            flush_completed = std::max(flush_completed, chunk.flush_id);
            continue;
        }

        if ( chunk.writer->finished )
            continue;

        chunk.writer->stats->dropped_writes += chunk.msgs.size();
        chunk.writer->stats->pending -= static_cast<int64_t>(chunk.msgs.size());
        dropped += chunk.msgs.size();
    }

    queue.clear();
    queued_bytes = 0;
    int64_t timeout_ms = stop_timeout_ms > 0 ? stop_timeout_ms : cfg.publisher.commit_timeout_ms;
    done_cv.notify_all();
    lock.unlock();

    if ( dropped > 0 )
        eprintf("%s: fast-ingest stopped with %" PRIu64 " queued writes, dropped", cfg.stream.c_str(), dropped);

    EndBatchIfReconnected();
    if ( ctx )
        EndBatch(/*commit=*/true, timeout_ms, NATS_OK);
}

void FastBatch::Publish(Chunk& chunk) {
    const auto& w = chunk.writer;
    size_t n = chunk.msgs.size();

    {
        // Already accounted as dropped by Finish().
        std::scoped_lock lock{mtx};
        if ( w->finished )
            return;
    }

    auto drop = [&](size_t from, const char* why) {
        size_t count = n - from;
        std::scoped_lock lock{mtx};
        if ( ! w->finished ) {
            w->stats->dropped_writes += count;
            w->stats->pending -= static_cast<int64_t>(count);
            eprintf("%s: Dropped %zu writes: %s", w->path.c_str(), count, why);
        }

        done_cv.notify_all();
    };

    uint64_t pre_wire_errors = 0;

    for ( size_t i = 0; i < n; i++ ) {
        // Publishing while disconnected would stall until the commit timeout.
        if ( ! conn->IsConnected() ) {
            if ( ctx )
                EndBatch(/*commit=*/false, 0, NATS_CONNECTION_DISCONNECTED);

            drop(i, "not connected");
            break;
        }

        // The server may have ended the batch asynchronously.
        if ( ctx && jsFastPublish_IsClosed(ctx) )
            EndBatch(/*commit=*/false, 0, NATS_ERR);

        EndBatchIfReconnected();

        if ( ! ctx && ! StartBatch() ) {
            drop(i, "could not start fast-ingest batch");
            break;
        }

        // Blocks for the first flow ack of a new batch, and while the
        // window of outstanding acks is full, at most the commit timeout.
        const auto& m = chunk.msgs[i];
        jsFastPubAck ack{};
        natsStatus s = jsFastPublish_Add(&ack, ctx, w->subject.c_str(), m.data(), static_cast<int>(m.size()), nullptr);
        if ( s == NATS_OK ) {
            sent = ack.BatchSequence;
            acked = std::max(acked, ack.AckSequence);
            last_publish_ms = nats_Now();
            Track(w, sent);
            continue;
        }

        if ( jsFastPublish_IsClosed(ctx) ) {
            // orbit.c closes the batch once a message reached the wire,
            // e.g. after an ack timeout, so its outcome is unknown. With
            // orbit.c's patch, ack also reports flow acks that arrived
            // while waiting. Commit what the server has, then continue
            // with a new batch.
            acked = std::max(acked, ack.AckSequence);
            Track(w, ++sent);
            EndBatch(/*commit=*/s == NATS_TIMEOUT, cfg.publisher.commit_timeout_ms, s);
            continue;
        }

        // Failed before reaching the wire, the batch is still open.
        debug("jsFastPublish_Add failed: %s", LastError(s));
        ++pre_wire_errors;
    }

    {
        std::scoped_lock lock{mtx};
        if ( pre_wire_errors > 0 && ! w->finished ) {
            w->stats->pending -= static_cast<int64_t>(pre_wire_errors);
            AccountErrors(*w, pre_wire_errors, 0, "publish failed");
        }

        ResolveLocked(acked);
        done_cv.notify_all();
    }
}

bool FastBatch::StartBatch() {
    jsFastPublisherOptions opts;
    jsFastPublisherOptions_Init(&opts);
    opts.Flow = cfg.publisher.flow;
    opts.MaxOutstandingAcks = cfg.publisher.max_outstanding_acks;
    opts.AckTimeout = cfg.publisher.commit_timeout_ms;
    opts.ContinueOnGap = cfg.publisher.continue_on_gap;
    opts.ErrHandler = _fastBatchErr;
    opts.ErrHandlerClosure = this;

    // Never connected, the server can't take a batch yet.
    if ( conn->Epoch() == 0 ) {
        debug("FastBatch start failed: not yet connected");
        return false;
    }

    if ( natsStatus s = jsFastPublishCtx_Create(&ctx, conn->RawConnection(), &opts); s != NATS_OK ) {
        debug("FastBatch start failed: %s", LastError(s));
        ctx = nullptr;
        return false;
    }

    sent = 0;
    acked = 0;
    last_publish_ms = nats_Now();
    batch_epoch = conn->Epoch();

    debug("FastBatch started");
    return true;
}

void FastBatch::EndBatchIfReconnected() {
    if ( ! ctx || conn->Epoch() == batch_epoch )
        return;

    // A server that kept the batch confirms it with the commit. Otherwise,
    // e.g. after a restart, messages since the last flow ack may or may not
    // have been persisted before.
    debug("FastBatch: connection reconnected, ending the batch");
    EndBatch(/*commit=*/true, cfg.publisher.commit_timeout_ms, NATS_CONNECTION_DISCONNECTED, /*outcome_unknown=*/true);
}

void FastBatch::EndBatch(bool commit, int64_t timeout_ms, natsStatus reason, bool outcome_unknown) {
    uint64_t confirmed = acked;

    if ( commit && sent > 0 ) {
        // With orbit.c's patch, this also commits batches closed by an ack
        // timeout, confirming what the server persisted meanwhile.
        jsPubAck* pa = nullptr;
        if ( natsStatus s =
                 jsFastPublish_Close(&pa, ctx, timeout_ms > 0 ? timeout_ms : cfg.publisher.commit_timeout_ms);
             s == NATS_OK ) {
            // Count is the batch sequence of the last message, the commit
            // ack confirms the whole batch.
            if ( pa ) {
                confirmed = std::max(confirmed, pa->Count);
                jsPubAck_Destroy(pa);
            }
        }
        else {
            debug("jsFastPublish_Close failed: %s", natsStatus_GetText(s));
            if ( reason == NATS_OK || s == NATS_TIMEOUT )
                reason = s;
        }
    }

    if ( reason == NATS_OK )
        reason = NATS_ERR;

    std::string error;
    {
        std::scoped_lock elock{errors_mtx};
        error = batch_error;
    }

    const char* why = error.empty() ? natsStatus_GetText(reason) : error.c_str();

    {
        std::scoped_lock lock{mtx};
        ResolveLocked(confirmed);

        // Anything left was neither confirmed nor reported failed.
        std::vector<std::pair<uint64_t, uint64_t>> lost;
        {
            std::scoped_lock elock{errors_mtx};
            lost = failed;
        }

        for ( const auto& r : inflight ) {
            if ( r.writer->finished )
                continue;

            uint64_t n = r.last - r.first + 1;
            uint64_t definite = overlap(lost, r.first, r.last);
            uint64_t unknown = reason == NATS_TIMEOUT || outcome_unknown ? n - definite : 0;
            r.writer->stats->pending -= static_cast<int64_t>(n);
            AccountErrors(*r.writer, n - unknown, unknown, why);
        }

        inflight.clear();
        done_cv.notify_all();
    }

    // Waits until the ack handler can't run anymore, so clearing the
    // failures afterwards doesn't race with late reports.
    jsFastPublish_Destroy(ctx);
    ctx = nullptr;
    sent = 0;
    acked = 0;

    {
        std::scoped_lock elock{errors_mtx};
        failed.clear();
        batch_error.clear();
    }

    debug("FastBatch ended");
}

void FastBatch::Track(const std::shared_ptr<FastBatchWriter>& w, uint64_t seq) {
    if ( ! inflight.empty() && inflight.back().writer == w && inflight.back().last + 1 == seq ) {
        inflight.back().last = seq;
        return;
    }

    inflight.push_back(InFlight{seq, seq, w});
}

void FastBatch::ResolveLocked(uint64_t seq) {
    if ( inflight.empty() || inflight.front().first > seq )
        return;

    std::vector<std::pair<uint64_t, uint64_t>> lost;
    {
        std::scoped_lock elock{errors_mtx};
        lost = failed;
    }

    while ( ! inflight.empty() && inflight.front().first <= seq ) {
        auto& r = inflight.front();
        uint64_t last = std::min(r.last, seq);

        if ( ! r.writer->finished ) {
            uint64_t n = last - r.first + 1;
            uint64_t definite = overlap(lost, r.first, last);
            r.writer->stats->publish_acks += n - definite;
            r.writer->stats->pending -= static_cast<int64_t>(n);
            AccountErrors(*r.writer, definite, 0, "messages lost by the server");
        }

        if ( last == r.last )
            inflight.pop_front();
        else
            r.first = last + 1;
    }
}

void FastBatch::AccountErrors(FastBatchWriter& w, uint64_t errors, uint64_t timeouts, const char* reason) {
    // Log the first one and whenever a multiple of publish_error_log is
    // crossed, like NATSWriter::PublishError().
    auto account = [&](std::atomic<uint64_t>& counter, uint64_t n, const char* what) {
        if ( n == 0 )
            return;

        uint64_t prev = counter.fetch_add(n);
        uint64_t now = prev + n;
        if ( cfg.publish_error_log == 0 )
            return;

        if ( prev == 0 || prev / cfg.publish_error_log != now / cfg.publish_error_log )
            eprintf("%s: %s: %s [stream=%s n=%" PRIu64 " total=%" PRIu64 "]", w.path.c_str(), what,
                    reason ? reason : "<null>", cfg.stream.c_str(), n, now);
    };

    account(w.stats->publish_errors, errors, "PublishError");
    account(w.stats->publish_timeouts, timeouts, "PublishTimeout (outcome unknown)");
}
