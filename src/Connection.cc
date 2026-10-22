#include "Connection.h"

#include <nats/nats.h>
#include <cstdio>

#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

namespace {

// The callbacks for connection handling.

void connected_cb(natsConnection* nc, void* closure) {
    using Connection::ConnectionCallbackType::CONNECTED;

    auto* holder = static_cast<std::shared_ptr<CallbackState>*>(closure);
    auto& state = *holder;
    std::scoped_lock lock{state->mtx};

    if ( state->conn )
        state->conn->ConnectionCallback(nc, CONNECTED);
}

void reconnected_cb(natsConnection* nc, void* closure) {
    using Connection::ConnectionCallbackType::RECONNECTED;

    auto* holder = static_cast<std::shared_ptr<CallbackState>*>(closure);
    auto& state = *holder;
    std::scoped_lock lock{state->mtx};

    if ( state->conn )
        state->conn->ConnectionCallback(nc, RECONNECTED);
}

void disconnected_cb(natsConnection* nc, void* closure) {
    using Connection::ConnectionCallbackType::DISCONNECTED;

    auto* holder = static_cast<std::shared_ptr<CallbackState>*>(closure);
    auto& state = *holder;

    std::scoped_lock lock{state->mtx};
    if ( state->conn )
        state->conn->ConnectionCallback(nc, DISCONNECTED);
}

void closed_cb(natsConnection* nc, void* closure) {
    using Connection::ConnectionCallbackType::CLOSED;

    auto* holder = static_cast<std::shared_ptr<CallbackState>*>(closure);
    auto& state = *holder;

    {
        std::scoped_lock lock{state->mtx};
        if ( state->conn )
            state->conn->ConnectionCallback(nc, CLOSED);
    }

    // delete outside of lock, otherwise use-after-free!
    delete holder;
}

/**
 * Helper class for defer.
 */
class Defer {
public:
    Defer(std::function<void()> f) : f(f) {}

    ~Defer() { f(); }

private:
    std::function<void()> f;
};

} // namespace

Connection::Connection(ConnectionOptions opts) : opts(std::move(opts)) {}

Connection::~Connection() {
    if ( cb_state ) {
        // Unset conn such that the CLOSED callback
        // will delete cb_state.
        std::scoped_lock lock{cb_state->mtx};
        cb_state->conn = nullptr;
    }

    if ( natsConn )
        natsConnection_Destroy(natsConn);
}

Result Connection::StartConnect() {
    if ( natsConn ) {
        eprintf("StartConnect() called twice???");
        return Ok();
    }

    debug("StartConnect timeout_ms=%" PRId64 " ping_interval_ms=%" PRId64 " reconnect_wait_ms=%" PRId64
          " jitter_ms=%" PRId64 " jitter_tls_ms=%" PRId64,
          opts.connection_timeout_ms, opts.ping_interval_ms, opts.reconnect_wait_ms, opts.jitter_ms,
          opts.jitter_tls_ms);


    natsStatus s;
    natsOptions* natsOpts = nullptr;

    if ( s = natsOptions_Create(&natsOpts); s != NATS_OK )
        return Error("Could not create options");

    cb_state = std::make_shared<CallbackState>(this);

    // The "holder" is a heap allocated shared_ptr using the cb_state
    // control block. It's passed as closure to connection callbacks
    // for those to find the connection. It's deleted in the closed_cb
    // which will reduce the reference count of the original cb_state.
    auto* tmp_holder = new std::shared_ptr<CallbackState>(cb_state);

    Defer defer([natsOpts, &tmp_holder]() {
        natsOptions_Destroy(natsOpts);

        if ( tmp_holder )
            delete tmp_holder;
    });

    if ( s = natsOptions_SetURL(natsOpts, opts.url.c_str()); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetURL: " + error);
    }

    if ( s = natsOptions_SetTimeout(natsOpts, opts.connection_timeout_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetTimeout: " + error);
    }

    if ( s = natsOptions_SetAllowReconnect(natsOpts, true); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetAllowReconnect: " + error);
    }

    if ( s = natsOptions_SetReconnectWait(natsOpts, opts.reconnect_wait_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetReconnectWait: " + error);
    }

    if ( s = natsOptions_SetMaxReconnect(natsOpts, opts.max_reconnect); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetMaxReconnect: " + error);
    }

    if ( s = natsOptions_SetReconnectedCB(natsOpts, reconnected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetReconnectedCB: " + error);
    }

    if ( s = natsOptions_SetClosedCB(natsOpts, closed_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetClosedCB: " + error);
    }

    if ( s = natsOptions_SetDisconnectedCB(natsOpts, disconnected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetDisconnectedCB: " + error);
    }

    if ( s = natsOptions_SetRetryOnFailedConnect(natsOpts, /*retry=*/true, connected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetRetryOnFailedConnect: " + error);
    }

    if ( s = natsOptions_SetReconnectJitter(natsOpts, opts.jitter_ms, opts.jitter_tls_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        natsOptions_Destroy(natsOpts);
        return Error("Failed to SetReconnectJitter: " + error);
    }

    if ( s = natsOptions_SetPingInterval(natsOpts, opts.ping_interval_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to SetRetryOnFailedConnect: " + error);
    }

    if ( s = natsConnection_Connect(&natsConn, natsOpts); (s != NATS_OK && s != NATS_NOT_YET_CONNECTED) ) {
        std::string error = nats_GetLastError(nullptr);
        natsOptions_Destroy(natsOpts);
        return Error(error + "[url=" + opts.url + "]");
    }

    // Ensure ~Defer() won't delete it.
    tmp_holder = nullptr;

    // Initialize epoch with 1 if it's already ready, otherwise
    // the connect_cb will set epoch appropriately.
    epoch = s == NATS_NOT_YET_CONNECTED ? 0 : 1;

    // Log a connected messages - happens in connected_cb otherwise.
    if ( epoch == 1 )
        eprintf("Connected!");

    return Ok();
}

void Connection::ConnectionCallback(natsConnection* nc, ConnectionCallbackType type) {
    // Short-circuit at shutdown shutdown.
    if ( natsConn == nullptr &&
         (type == ConnectionCallbackType::CLOSED || type == ConnectionCallbackType::DISCONNECTED) )
        return;

    if ( nc != natsConn ) {
        eprintf("Ignoring ReconnectCallback() for wrong connection nc=%p natsConn=%p type=%d! Bug???", nc, natsConn,
                static_cast<int>(type));
        return;
    }

    switch ( type ) {
        case ConnectionCallbackType::CONNECTED: {
            natsConn = nc;
            if ( epoch != 0 )
                eprintf("Unexpected epoch in CONNECTED callback! %" PRIu64, epoch.load());
            epoch = 1;

            eprintf("Connected!");
            break;
        }
        case ConnectionCallbackType::RECONNECTED: {
            ++epoch;
            eprintf("Reconnected natsConn=%p epoch=%" PRIu64, natsConn, epoch.load());
            break;
        }
        case ConnectionCallbackType::DISCONNECTED: {
            eprintf("Disconnected natsConn=%p epoch=%" PRIu64, natsConn, epoch.load());
            break;
        }
        case ConnectionCallbackType::CLOSED: {
            // This happens at shutdown.
            eprintf("Connection closed natsconn=%p", natsConn);

            if ( epoch == 0 ) {
                // XXX: Should only get here if the initial connection wasn't
                //      properly established and the first StartConnect()
                //      returned NATS_NOT_YET_CONNECTED.
                //
                // In nats.c, there's was a bug that was fixed with commit
                // 77843e72 (3.15, Oct 17, 2025) that would cause CLOSED
                // callbacks in these scenarios. This branch should not be
                // reached with version 3.15 or later.
                //
                // Destroy this connection (safe?) and initiate another
                // StartConnect() immediately. The outer closed_cb()
                // will delete cb_state.
                cb_state->conn = nullptr;
                cb_state = nullptr;

                natsConnection_Destroy(natsConn);
                natsConn = nullptr;

                StartConnect();
            }

            break;
        }
        default: {
            // This should never happen.
            eprintf("Unexpected %d callback!", static_cast<int>(type));
            abort();
        }
    }
}


Result Connection::JetStream(jsCtx** js, int64_t publish_async_max_pending, int64_t publish_async_stall_wait_ms,
                             jsPubAckHandler ack_handler, void* ack_handler_closure) {
    natsStatus s;
    jsOptions jsOpts;

    // If we've never connected, do not hand out
    // a JetStream instance.
    if ( epoch == 0 )
        return Error("NATS connection not yet ready");

    if ( s = jsOptions_Init(&jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to init JetStream options: " + error);
    }

    jsOpts.PublishAsync.MaxPending = publish_async_max_pending;
    jsOpts.PublishAsync.StallWait = publish_async_stall_wait_ms;
    jsOpts.PublishAsync.AckHandler = ack_handler;
    jsOpts.PublishAsync.AckHandlerClosure = ack_handler_closure;

    debug("JetStream() natsConn=%p\n", natsConn);

    if ( s = natsConnection_JetStream(js, natsConn, &jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error("Failed to initialize JetStream: " + error);
    }

    return Ok();
}


std::shared_ptr<Connection> Connection::Create(ConnectionSharingPolicy sharing_policy, ConnectionOptions opts) {
    // If exclusive, just hand out a new connection.
    if ( sharing_policy == ConnectionSharingPolicy::EXCLUSIVE ) {
        auto conn = std::make_shared<Connection>(std::move(opts));
        conn->StartConnect();
        return conn;
    }

    std::string url = opts.url;

    // Lock the full connection table. Creating a connection
    // shouldn't be done very often, so this should be fine.
    std::shared_ptr<Connection> conn;
    std::scoped_lock lock{connections_mtx};
    auto it = connections.find(url);
    if ( it != connections.end() ) {
        conn = it->second.lock();
        if ( conn )
            return conn;
    }

    conn = std::make_shared<Connection>(std::move(opts));

    // Keep a weak-pointer for this connection around.
    connections[url] = conn;

    conn->StartConnect();
    return conn;
}

// Static connection members.
std::map<std::string, std::weak_ptr<Connection>> Connection::connections;
std::mutex Connection::connections_mtx;
