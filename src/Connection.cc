#include "Connection.h"

#include <nats/nats.h>
#include <nats/status.h>
#include <nats/version.h>
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
    std::shared_ptr<CallbackState> state;
    natsConnection* conn = nullptr;

    // Fetch current values under lock and unset natsConn
    // to avoid racing with the CLOSED callback.
    {
        std::scoped_lock lock{mtx};
        state = cb_state;
        conn = natsConn;
        natsConn = nullptr;
    }

    if ( state ) {
        // Unset conn such that the CLOSED callback
        // will delete cb_state.
        std::scoped_lock lock{state->mtx};
        state->conn = nullptr;
    }

    if ( conn )
        natsConnection_Destroy(conn);
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
        return Error(s, "Could not create options");

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
        return Error(s, "Failed to SetURL: " + error);
    }

    if ( s = natsOptions_SetTimeout(natsOpts, opts.connection_timeout_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetTimeout: " + error);
    }

    if ( s = natsOptions_SetAllowReconnect(natsOpts, true); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetAllowReconnect: " + error);
    }

    if ( s = natsOptions_SetReconnectWait(natsOpts, opts.reconnect_wait_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetReconnectWait: " + error);
    }

    if ( s = natsOptions_SetMaxReconnect(natsOpts, opts.max_reconnect); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetMaxReconnect: " + error);
    }

    if ( s = natsOptions_SetReconnectedCB(natsOpts, reconnected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetReconnectedCB: " + error);
    }

    if ( s = natsOptions_SetClosedCB(natsOpts, closed_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetClosedCB: " + error);
    }

    if ( s = natsOptions_SetDisconnectedCB(natsOpts, disconnected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetDisconnectedCB: " + error);
    }

    if ( s = natsOptions_SetRetryOnFailedConnect(natsOpts, /*retry=*/true, connected_cb, tmp_holder); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetRetryOnFailedConnect: " + error);
    }

    if ( s = natsOptions_SetReconnectJitter(natsOpts, opts.jitter_ms, opts.jitter_tls_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetReconnectJitter: " + error);
    }

    if ( s = natsOptions_SetPingInterval(natsOpts, opts.ping_interval_ms); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to SetRetryOnFailedConnect: " + error);
    }

    {
        // Start connecting with the lock held such that if natsConnection_Connect()
        // returns with NATS_NOT_YET_CONNECTED and the background thread immediately
        // invokes the connect_cb, we don't overwrite epoch with a stale value.
        // callback registered above
        std::scoped_lock lock{cb_state->mtx};

        if ( s = natsConnection_Connect(&natsConn, natsOpts); (s != NATS_OK && s != NATS_NOT_YET_CONNECTED) ) {
            std::string error = nats_GetLastError(nullptr);
            return Error(s, error + "[url=" + opts.url + "]");
        }

        // Ensure ~Defer() won't delete it.
        tmp_holder = nullptr;

        // Initialize epoch with 1 if it's already ready, otherwise
        // the connect_cb will set epoch appropriately.
        epoch = s == NATS_NOT_YET_CONNECTED ? 0 : 1;

        // Log a connected messages - happens in connected_cb otherwise.
        if ( epoch == 1 )
            eprintf("Connected [pid=%d natsConn=%p epoch=%" PRIu64 "]", getpid(), natsConn, epoch.load());
    }

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

            eprintf("Connected [pid=%d natsConn=%p epoch=%" PRIu64 "]", getpid(), natsConn, epoch.load());
            break;
        }
        case ConnectionCallbackType::RECONNECTED: {
            ++epoch;
            eprintf("Reconnected [pid=%d natsConn=%p epoch=%" PRIu64 "]", getpid(), natsConn, epoch.load());
            break;
        }
        case ConnectionCallbackType::DISCONNECTED: {
            eprintf("Disconnected [pid=%d natsConn=%p epoch=%" PRIu64 "]", getpid(), natsConn, epoch.load());
            break;
        }
        case ConnectionCallbackType::CLOSED: {
            // This happens at shutdown.
            eprintf("Closed [pid=%d natsConn=%p epoch=%" PRIu64 "]", getpid(), natsConn, epoch.load());

            if ( epoch == 0 ) {
                // XXX: Should only get here if the initial connection wasn't
                //      properly established and the first StartConnect()
                //      returned NATS_NOT_YET_CONNECTED and running < 3.12.
                //      Remove this all when the plugin depends on >=3.12.
                //
                // In nats.c, there's was a bug that was fixed with commit
                // 77843e72 (3.12, Oct 17, 2025) that would cause CLOSED
                // callbacks in these scenarios. This branch should not be
                // reached with version 3.12 or later.
                //
                // Destroy this connection (safe?) and initiate another
                // StartConnect() immediately. The outer closed_cb()
                // will delete cb_state.
#if NATS_VERSION_MAJOR > 3 || (NATS_VERSION_MAJOR == 3 && NATS_VERSION_MINOR >= 12)
                eprintf("Unexpected CLOSED event!");
#endif
                {
                    // Modify these under the Connection's lock.
                    std::scoped_lock lock{mtx};
                    cb_state->conn = nullptr;
                    cb_state = nullptr;

                    // Unless the destructor unset natsConn, destroy it
                    // and attempt to reconnect.
                    if ( natsConn ) {
                        natsConnection_Destroy(natsConn);
                        natsConn = nullptr;

                        if ( auto [ok, status, error] = StartConnect(); ! ok ) {
                            // This should really not fail here, just be loud.
                            eprintf("Unexpected StartConnect error: %s", error->c_str());
                        }
                    }
                }
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
    natsStatus s = NATS_OK;
    jsOptions jsOpts;

    // If we've never connected, do not hand out
    // a JetStream instance.
    if ( epoch == 0 )
        return Error(NATS_ERR, "NATS connection not yet ready");

    if ( s = jsOptions_Init(&jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to init JetStream options: " + error);
    }

    jsOpts.PublishAsync.MaxPending = publish_async_max_pending;
    jsOpts.PublishAsync.StallWait = publish_async_stall_wait_ms;
    jsOpts.PublishAsync.AckHandler = ack_handler;
    jsOpts.PublishAsync.AckHandlerClosure = ack_handler_closure;

    debug("JetStream() natsConn=%p\n", natsConn);

    if ( s = natsConnection_JetStream(js, natsConn, &jsOpts); s != NATS_OK ) {
        *js = nullptr;
        std::string error = nats_GetLastError(nullptr);
        return Error(s, "Failed to initialize JetStream: " + error);
    }

    return Ok();
}


Result Connection::Publish(natsMsg* msg) {
    natsStatus s;

// Older version
#if NATS_VERSION_MAJOR == 3 && NATS_VERSION_MINOR < 12
    if ( epoch == 0 )
        return Error(NATS_ERR, "NATS connection not yet ready");
#endif

    if ( s = natsConnection_PublishMsg(natsConn, msg); s != NATS_OK ) {
        std::string error = nats_GetLastError(nullptr);
        return Error(s, std::move(error));
    }

    return Ok();
}


FastPublisherPtr Connection::CreateFastPublisher(FastPublishBatchPolicy policy, FastPublisherOptions opts) {
    if ( Epoch() == 0 ) {
        eprintf("CreateFastPublisher: not yet connected!\n");
        return nullptr;
    }

    if ( policy == FastPublishBatchPolicy::EXCLUSIVE )
        return std::make_shared<FastPublisher>(shared_from_this(), std::move(opts));
    else if ( policy == FastPublishBatchPolicy::SHARED ) {
        {
            // Should't be hot.
            std::scoped_lock lock{mtx};
            if ( ! shared_publisher )
                shared_publisher = std::make_shared<SharedFastPublisher>(shared_from_this(), std::move(opts));

            return shared_publisher;
        }
    }

    eprintf("Unexpected\n");

    return nullptr;
}


Connection::CreateResult Connection::Create(ConnectionSharingPolicy sharing_policy, ConnectionOptions opts) {
    // If exclusive, just hand out a new connection.
    if ( sharing_policy == ConnectionSharingPolicy::EXCLUSIVE ) {
        auto conn = std::make_shared<Connection>(std::move(opts));
        if ( auto [ok, status, error] = conn->StartConnect(); ! ok )
            return {false, nullptr, *error};

        return {true, conn, std::nullopt};
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
            return {true, conn, std::nullopt};
    }

    conn = std::make_shared<Connection>(std::move(opts));

    // Keep a weak-pointer for this connection around.
    connections[url] = conn;

    if ( auto [ok, status, error] = conn->StartConnect(); ! ok ) {
        connections.erase(url);
        return {false, nullptr, *error};
    }

    return {true, conn, std::nullopt};
}

// Static connection members.
std::map<std::string, std::weak_ptr<Connection>> Connection::connections;
std::mutex Connection::connections_mtx;


//
// FastPublisher code below
//

namespace {
void fp_err_handler(natsStatus status, const char* description, void* closure) {
    auto* fast_publisher = static_cast<FastPublisher*>(closure);
    fast_publisher->ErrorHandler(status, description);
}
} // namespace


FastPublisher::FastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts)
    : conn(std::move(conn)), opts(std::move(opts)) {
    debug("FastPublisher constructor");
}


FastPublisher::~FastPublisher() {
    // Poor man.
    debug("FastPublisher destructor");
}


Result FastPublisher::DoAddMsg(natsMsg* msg, const char* subject, const void* data, int data_len) {
    natsStatus s = NATS_OK;

    // Update idle timestamp
    idle_ts = nats_Now();

    if ( ! fp_ctx ) {
        // debug("AddMsg(): Creating new batch!\n");
        jsFastPublisherOptions fp_opts;
        if ( s = jsFastPublisherOptions_Init(&fp_opts); s != NATS_OK )
            return Error(s, "failed to create options");

        fp_opts.ErrHandler = fp_err_handler;
        fp_opts.ErrHandlerClosure = this; // do we also need some callback state as indirection here?
        fp_opts.Flow = opts.flow;
        fp_opts.MaxOutstandingAcks = opts.max_outstanding_acks;
        fp_opts.ContinueOnGap = opts.continue_on_gap;

        natsConnection* nc = conn->RawConnection();

        // Create a batch here if needed. It'll be committed
        // when it is full, or in DoHeartbeat() or DoFinish().
        if ( s = jsFastPublishCtx_Create(&fp_ctx, nc, &fp_opts); s != NATS_OK ) {
            eprintf("jsPublishCtx_Create failed");
            std::string error = nats_GetLastError(nullptr);
            return Error(s, error);
        }
    }

    // How much more room in the batch before we commit? Zero means
    const size_t left = opts.max_batch_size == 0 ? 0 : opts.max_batch_size - batch_size;

    // Do we need BatchMsgOpts
    // jsBatchMsgOpts opts;
    // jsBatchMsgOpts_Init()

    // left == 0: unlimited, left > 1: still room.
    if ( left == 0 || left > 1 ) {
        if ( msg )
            s = jsFastPublish_AddMsg(/*ack=*/nullptr, fp_ctx, msg, /*opts=*/nullptr);
        else
            s = jsFastPublish_Add(/*ack=*/nullptr, fp_ctx, subject, data, data_len, /*opts=*/nullptr);

        if ( s != NATS_OK )
            return Error(s, "AddMsg failed");

        ++batch_size;
    }
    else if ( left == 1 ) {
        // max_batch_size reached
        jsPubAck* pub_ack = nullptr;
        // debug("AddMsg: Batch full, commit!\n");

        if ( msg )
            s = jsFastPublish_CommitMsg(&pub_ack, fp_ctx, msg, /*opts=*/nullptr, opts.commit_timeout_ms);
        else
            s = jsFastPublish_Commit(&pub_ack, fp_ctx, subject, data, data_len, /*opts=*/nullptr,
                                     opts.commit_timeout_ms);

        if ( s != NATS_OK ) {
            std::string error = nats_GetLastError(nullptr);
            eprintf("CommitMsg failed -- really bad: %s\n", error.c_str());
            // PublishError(s, 0, "jsFastPublish_CommitMsg() failed");
        }
        else {
            debug("Commit this=%p Sequence=%" PRIu64 " Count=%" PRIu64, this, pub_ack->Sequence, pub_ack->Count);

            jsPubAck_Destroy(pub_ack); // should we do something with it? metrics?
            pub_ack = nullptr;
        }

        jsFastPublish_Destroy(fp_ctx);
        fp_ctx = nullptr;
        batch_size = 0;
    }
    else {
        eprintf("unexpected left %zu", left);
        abort();
    }

    return Ok();
}


Result FastPublisher::Commit() {
    if ( ! fp_ctx )
        return Ok();

    natsStatus s = NATS_OK;
    jsPubAck* pub_ack = nullptr;

    if ( s = jsFastPublish_Close(&pub_ack, fp_ctx, opts.commit_timeout_ms); s != NATS_OK ) {
        std::string status_str = natsStatus_GetText(s);

        // TODO: Metric
        eprintf("jsFastPublish_Close() failed: %s", status_str.c_str());
        return Error(s, status_str);
    }

    debug("Commit this=%p Sequence=%" PRIu64 " Count=%" PRIu64, this, pub_ack->Sequence, pub_ack->Count);

    jsPubAck_Destroy(pub_ack); // should we do something with it? metrics?
    pub_ack = nullptr;
    jsFastPublish_Destroy(fp_ctx);

    fp_ctx = nullptr;
    batch_size = 0;

    return Ok();
}


void FastPublisher::ErrorHandler(natsStatus status, const char* description) {
    const char* status_str = natsStatus_GetText(status);
    eprintf("ERROR %s: %s", status_str, description);

    // Not really sure what to do here? Just log an error, increment
    // some error and move on?
}


SharedFastPublisher::SharedFastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts)
    : FastPublisher(std::move(conn), std::move(opts)) {
    debug("SharedFastPublisher constructor this=%p", this);
}
