#include "SharedClient.h"

#include <unistd.h>
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <utility>

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

std::atomic<int64_t> SharedClient::connections = 0;

namespace {

// Bounds for the delay between connection attempts.
constexpr auto min_connect_backoff = std::chrono::seconds(1);
constexpr auto max_connect_backoff = std::chrono::seconds(30);

std::mutex registry_mtx;

std::map<std::string, std::weak_ptr<SharedClient>>& registry() {
    // Leaked intentionally to avoid static destruction order issues
    // with writers destroyed late during shutdown.
    static auto* r = new std::map<std::string, std::weak_ptr<SharedClient>>();
    return *r;
}

void _jsPubAck(jsCtx* js, natsMsg* msg, jsPubAck* pa, jsPubAckErr* pae, void* closure) {
    static_cast<SharedClient*>(closure)->OnPublishAck(msg, pa, pae);
    natsMsg_Destroy(msg);
}

} // namespace

void NATSWriterStats::PublishError(int code, const char* text) {
    // May be called asynchronously and from DoWrite(), so don't use
    // Error() or Fmt() and instead go through fprintf and use a lock.
    static std::mutex mx;
    std::lock_guard lock(mx);
    if ( publish_error_log > 0 ) {
        if ( publish_errors % publish_error_log == 0 ) {
            std::fprintf(stderr, "NATS/%s: PublishError: %s [pid=%d code=%d publish_errors=%" PRIu64 "]\n",
                         name.c_str(), text, getpid(), code, publish_errors + 1);
        }
    }

    publish_errors++;
}

std::shared_ptr<SharedClient> SharedClient::Acquire(const SharedClientOptions& opts) {
    std::lock_guard lock(registry_mtx);
    auto& r = registry();

    if ( auto it = r.find(opts.url); it != r.end() ) {
        if ( auto client = it->second.lock() )
            return client;
    }

    auto client = std::make_shared<SharedClient>(opts);
    r[opts.url] = client;
    return client;
}

SharedClient::SharedClient(SharedClientOptions arg_opts) : opts(std::move(arg_opts)), rng(std::random_device{}()) {}

SharedClient::~SharedClient() {
    // Close first so no more acks are delivered to this instance.
    if ( conn )
        natsConnection_Close(conn);

    if ( js )
        jsCtx_Destroy(js);

    if ( conn ) {
        natsConnection_Destroy(conn);
        --connections;
    }

    if ( nats_opts )
        natsOptions_Destroy(nats_opts);

    std::lock_guard lock(registry_mtx);
    auto& r = registry();
    // A new client for the same URL may have been registered after
    // the last reference to this one was dropped. Leave it in place.
    if ( auto it = r.find(opts.url); it != r.end() && it->second.expired() )
        r.erase(it);
}

std::chrono::steady_clock::duration SharedClient::NextBackoff() {
    // Exponential backoff with full jitter, but at least min_connect_backoff
    // so that a co-located server that's still starting isn't hammered.
    std::chrono::seconds ceiling = max_connect_backoff;
    if ( connect_failures < 5 )
        ceiling = std::min(ceiling, min_connect_backoff * (1 << connect_failures));

    std::uniform_int_distribution<int64_t> dist(0, std::chrono::milliseconds(ceiling).count());
    auto backoff = std::chrono::milliseconds(dist(rng));
    return std::max<std::chrono::steady_clock::duration>(backoff, min_connect_backoff);
}

jsCtx* SharedClient::JetStream(std::string* error) {
    if ( auto* j = js.load() )
        return j;

    // If another writer is attempting to connect, wait for its result
    // rather than dropping writes or attempting to connect in parallel.
    std::lock_guard lock(connect_mtx);
    if ( auto* j = js.load() )
        return j;

    auto now = std::chrono::steady_clock::now();
    if ( now < next_connect_attempt )
        return nullptr;

    natsStatus s = NATS_OK;
    auto fail = [&](const char* what) -> jsCtx* {
        *error = std::string(what) + ": " + nats_GetLastError(nullptr);
        next_connect_attempt = now + NextBackoff();
        ++connect_failures;
        return nullptr;
    };

    if ( ! nats_opts ) {
        if ( s = natsOptions_Create(&nats_opts); s != NATS_OK )
            return fail("Could not create options");

        if ( s = natsOptions_SetURL(nats_opts, opts.url.c_str()); s != NATS_OK ) {
            natsOptions_Destroy(nats_opts);
            nats_opts = nullptr;
            return fail(("Failed to SetURL " + opts.url).c_str());
        }

        // Make the connection identifiable on the server, e.g. via connz.
        std::string name = "zeek-log-writer-nats/" + std::to_string(getpid());
        if ( s = natsOptions_SetName(nats_opts, name.c_str()); s != NATS_OK ) {
            natsOptions_Destroy(nats_opts);
            nats_opts = nullptr;
            return fail("Failed to SetName");
        }
    }

    if ( s = natsConnection_Connect(&conn, nats_opts); s != NATS_OK )
        return fail(("Failed to connect to " + opts.url).c_str());

    jsOptions js_opts;
    jsOptions_Init(&js_opts);
    js_opts.PublishAsync.MaxPending = opts.publish_async_max_pending;
    js_opts.PublishAsync.AckHandler = _jsPubAck;
    js_opts.PublishAsync.AckHandlerClosure = this;
    js_opts.PublishAsync.StallWait = opts.publish_async_stall_wait_ms;

    jsCtx* new_js = nullptr;
    if ( s = natsConnection_JetStream(&new_js, conn, &js_opts); s != NATS_OK ) {
        natsConnection_Destroy(conn);
        conn = nullptr;
        return fail("Failed to initialize JetStream");
    }

    ++connections;
    connect_failures = 0;
    js = new_js;
    return new_js;
}

void SharedClient::RegisterStats(const std::string& subject, std::shared_ptr<NATSWriterStats> stats) {
    std::lock_guard lock(stats_mtx);
    stats_by_subject[subject].push_back(std::move(stats));
}

void SharedClient::UnregisterStats(const std::string& subject, const std::shared_ptr<NATSWriterStats>& stats) {
    std::lock_guard lock(stats_mtx);
    auto it = stats_by_subject.find(subject);
    if ( it == stats_by_subject.end() )
        return;

    std::erase(it->second, stats);
    if ( it->second.empty() )
        stats_by_subject.erase(it);
}

std::shared_ptr<NATSWriterStats> SharedClient::LookupStats(const char* subject) {
    if ( ! subject )
        return nullptr;

    std::lock_guard lock(stats_mtx);
    if ( auto it = stats_by_subject.find(std::string_view(subject)); it != stats_by_subject.end() )
        return it->second.front();

    return nullptr;
}

void SharedClient::OnPublishAck(natsMsg* msg, jsPubAck* pa, jsPubAckErr* pae) {
    ++responses;

    // Acks for messages of a writer that has since been removed are ignored.
    auto stats = LookupStats(natsMsg_GetSubject(msg));
    if ( ! stats )
        return;

    if ( pa != nullptr )
        ++stats->publish_acks;
    else if ( pae != nullptr )
        stats->PublishError(pae->ErrCode, pae->ErrText);
}
