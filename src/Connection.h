#pragma once

#include <nats/nats.h>
#include <nats/status.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>

#ifdef HAVE_ORBIT_FAST_PUBLISH
#include <fast_publish.h>
#endif

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

// Go'ish result type
using Result = std::tuple<bool, natsStatus, std::optional<std::string>>;

inline Result Ok() { return Result{true, NATS_OK, std::nullopt}; }
inline Result Error(natsStatus status, std::string msg) { return {false, status, std::move(msg)}; }

/**
 * The last libnats error of the calling thread, never NULL.
 *
 * libnats and orbit.c don't set an error for every failure, in which case
 * nats_GetLastError() returns NULL. Falls back to the text of status s.
 */
inline const char* LastError(natsStatus s) {
    if ( const char* error = nats_GetLastError(nullptr); error && *error )
        return error;

    if ( const char* text = natsStatus_GetText(s); text )
        return text;

    return "unknown error";
}


/**
 * Sharing policy for ConnectionFactory::Create()
 */
enum class ConnectionSharingPolicy {
    EXCLUSIVE,
    SHARED,
};

/**
 * Options for a connection.
 */
struct ConnectionOptions {
    std::string url;
    int max_reconnect = -1;
    int64_t connection_timeout_ms = 1000;
    int64_t ping_interval_ms = 5000;
    int64_t reconnect_wait_ms = 200;
    int64_t jitter_ms = 200;
    int64_t jitter_tls_ms = 200;
};


class Connection;
class FastBatch;

/**
 * This is used as the closure for the connection callbacks.
 *
 * The CLOSED callback deletes it.
 */
struct CallbackState {
    CallbackState(Connection* c) : conn(c) {}

    std::mutex mtx;
    Connection* conn = nullptr;
};

/**
 * A connection to a NATS server with an accessor
 * to allocate a low-level JetStream context.
 *
 * There's currently two implementations, a ExclusiveConnection and a
 * SharedConnection. The latter allows multiple threads to re-use the
 * same connection to a NATS server.
 */
class Connection {
public:
    Connection(ConnectionOptions opts);
    virtual ~Connection();

    /**
     * Starts connecting to the configured NATS servers.
     */
    Result StartConnect();

    enum class ConnectionCallbackType {
        CONNECTED,
        RECONNECTED,
        DISCONNECTED,
        CLOSED,
    };

    /**
     * Handle connection callbacks.
     */
    virtual void ConnectionCallback(natsConnection* nc, ConnectionCallbackType type);

    /**
     * Creates a new JetStream instance for a writer.
     *
     * Caller must destroy it.
     *
     * XXX: Taking a short-cut here, Might be nice to encapsulate
     * this into a dedicated JetStream class to manage lifetime.
     *
     * @param publish_async_max_pending
     * @param publish_async_stall_wait_ms
     * @param ack_handler Used for callback handling
     * @param ack_handler_closure Used for the ack_handler as closure
     *
     * @return Ok or Error, if OK, js is filled.
     */
    Result JetStream(jsCtx** js, int64_t publish_async_max_pending, int64_t publish_async_stall_wait_ms,
                     jsPubAckHandler ack_handler, void* ack_handler_closure);

#ifdef HAVE_ORBIT_FAST_PUBLISH
    /**
     * Creates a new fast-ingest batch publisher (ADR-50) on this connection.
     *
     * Caller must destroy it with jsFastPublish_Destroy() before
     * releasing the connection.
     *
     * @param ctx Filled on success.
     * @param opts Flow control options, read during the call.
     *
     * @return Ok or Error, if OK, ctx is filled.
     */
    Result FastPublisher(jsFastPublishCtx** ctx, jsFastPublisherOptions* opts);

    /**
     * Returns the fast-ingest batch shared by all writers of this
     * connection publishing to the given stream, creating it if
     * needed, and registers the caller with it. The options of the
     * first caller are used.
     *
     * The caller must call FastBatch::Release() and drop the
     * reference before releasing the connection.
     */
    std::shared_ptr<FastBatch> AcquireFastBatch(const std::string& stream, const jsFastPublisherOptions& opts,
                                                int64_t idle_timeout_ms);
#endif

    /**
     * @return true if the underlying connection is currently connected.
     */
    bool IsConnected();

    /**
     * The epoch is an increasing counter for when the underlying connection has changed.
     *
     * It starts with 0, meaning unconnected and increases with each new reconnection.
     */
    uint64_t Epoch() { return epoch; }

    /**
     * Publish the given low-level message on the underlying natsConnection.
     */
    Result Publish(natsMsg* msg);

    /**
     * Helper tuple returned from Create()
     */
    using CreateResult = std::tuple<bool, std::shared_ptr<Connection>, std::optional<std::string>>;

    /**
     * Create a new NATS connection using the given connection sharing policy.
     *
     * The connection may or may not be already connected when this call
     * returns. The underlying libnats library will retry unless the options
     * are invalid. If you get {false, null, error}, don't retry, something is
     * most likely wrong with the provided options. Check the error message.
     */
    static CreateResult Create(ConnectionSharingPolicy policy, ConnectionOptions opts);

protected:
    ConnectionOptions opts;
    natsConnection* natsConn = nullptr;

    // Deleted in closed_cb(), set in StartConnect()
    std::shared_ptr<CallbackState> cb_state;

    // Protect setting of natsConn and cb_state.
    //
    // TODO: Remove this and its usages when the nats.c dependency is
    // upgraded to >=3.12 CLOSED callback, it shouldn't be needed.
    std::mutex mtx;

private:
#ifdef HAVE_ORBIT_FAST_PUBLISH
    // One shared fast-ingest batch per stream.
    std::mutex fast_batches_mtx;
    std::map<std::string, std::weak_ptr<FastBatch>> fast_batches;
#endif

    std::atomic<uint64_t> epoch{0};
    static std::mutex connections_mtx;
    static std::map<std::string, std::weak_ptr<Connection>> connections;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
