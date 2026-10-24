#include "FastBatch.h"

#ifdef HAVE_ORBIT_FAST_PUBLISH

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
} // namespace

FastBatch::FastBatch(Connection* conn, const jsFastPublisherOptions& arg_opts, int64_t idle_timeout_ms)
    : conn(conn), opts(arg_opts), idle_timeout_ms(idle_timeout_ms) {
    opts.ErrHandler = _fastBatchErr;
    opts.ErrHandlerClosure = this;
}

FastBatch::~FastBatch() {
    if ( ctx )
        jsFastPublish_Destroy(ctx);
}

void FastBatch::Acquire() {
    std::scoped_lock lock{mtx};
    ++writers;
}

bool FastBatch::Release() {
    std::scoped_lock lock{mtx};
    return --writers == 0;
}

void FastBatch::OnError(natsStatus err, const char* text) {
    // Gaps report the number of messages lost.
    uint64_t expected_last = 0;
    uint64_t current = 0;
    if ( std::sscanf(text, "fast publish gap: expected_last=%" SCNu64 " current=%" SCNu64, &expected_last, &current) ==
         2 ) {
        async_failed += current > expected_last ? current - expected_last : 1;
        return;
    }

    // A single message failed, the batch continues.
    if ( std::strncmp(text, "fast publish error at sequence", 30) == 0 ) {
        ++async_failed;
        return;
    }

    // Everything else ends the batch.
    debug("FastBatch error: %s", text);
    std::scoped_lock lock{error_mtx};
    batch_error = text;
}

bool FastBatch::StartLocked() {
    if ( auto [ok, error] = conn->FastPublisher(&ctx, &opts); ! ok ) {
        debug("FastBatch start failed: %s", error ? error->c_str() : "<null>");
        return false;
    }

    {
        std::scoped_lock lock{error_mtx};
        batch_error.clear();
    }

    sent = 0;
    acked = 0;
    last_publish_ms = nats_Now();

    debug("FastBatch started");
    return true;
}

void FastBatch::EndLocked(bool commit, int64_t timeout_ms, FastBatchOutcome* out) {
    uint64_t confirmed = acked;
    natsStatus reason = NATS_ERR;

    if ( commit && sent > 0 && ! jsFastPublish_IsClosed(ctx) ) {
        jsPubAck* pa = nullptr;
        if ( natsStatus s = jsFastPublish_Close(&pa, ctx, timeout_ms); s == NATS_OK ) {
            // Count is the batch sequence of the last message, the commit
            // ack confirms the whole batch.
            if ( pa->Count > confirmed )
                confirmed = pa->Count;

            jsPubAck_Destroy(pa);
        }
        else {
            debug("jsFastPublish_Close failed: %s", natsStatus_GetText(s));
            reason = s;
        }
    }

    if ( confirmed > acked )
        out->acked += confirmed - acked;

    if ( sent > confirmed ) {
        out->unknown += sent - confirmed;
        out->reason = reason;
    }

    jsFastPublish_Destroy(ctx);
    ctx = nullptr;
    sent = 0;
    acked = 0;

    debug("FastBatch ended");
}

natsStatus FastBatch::AddMany(const char* subject, const std::vector<std::string>& msgs, size_t* published,
                              FastBatchOutcome* out) {
    std::scoped_lock lock{mtx};

    out->failed += async_failed.exchange(0);

    *published = 0;
    for ( const auto& m : msgs ) {
        if ( natsStatus s = AddLocked(subject, m.data(), static_cast<int>(m.size()), out); s != NATS_OK )
            return s;

        ++*published;
    }

    return NATS_OK;
}

natsStatus FastBatch::AddLocked(const char* subject, const char* data, int data_len, FastBatchOutcome* out) {
    // The server may have ended the batch asynchronously.
    if ( ctx && jsFastPublish_IsClosed(ctx) )
        EndLocked(/*commit=*/false, 0, out);

    // The server abandons batches without traffic for 10 seconds,
    // commit idle batches before that happens.
    int64_t now = nats_Now();
    if ( ctx && idle_timeout_ms > 0 && now - last_publish_ms >= idle_timeout_ms )
        EndLocked(/*commit=*/true, opts.AckTimeout, out);

    if ( ! ctx && ! StartLocked() ) {
        out->not_started = true;
        return NATS_ERR;
    }

    // Blocks for the first flow ack on a new batch, and when the window
    // of outstanding acks is full, at most AckTimeout. Other writers wait
    // on mtx meanwhile, which is the backpressure.
    jsFastPubAck ack;
    natsStatus s = jsFastPublish_Add(&ack, ctx, subject, data, data_len, nullptr);
    if ( s == NATS_OK ) {
        last_publish_ms = now;
        sent = ack.BatchSequence;
        if ( ack.AckSequence > acked ) {
            out->acked += ack.AckSequence - acked;
            acked = ack.AckSequence;
        }

        return NATS_OK;
    }

    // orbit.c doesn't always set a libnats error, e.g. on stall timeouts.
    {
        std::scoped_lock elock{error_mtx};
        out->error = batch_error;
    }

    if ( out->error.empty() )
        out->error = LastError(s);

    if ( jsFastPublish_IsClosed(ctx) )
        EndLocked(/*commit=*/false, 0, out);

    return s;
}

void FastBatch::Commit(int64_t timeout_ms, FastBatchOutcome* out) {
    std::scoped_lock lock{mtx};

    out->failed += async_failed.exchange(0);

    if ( ctx )
        EndLocked(/*commit=*/true, timeout_ms, out);
}

#endif
