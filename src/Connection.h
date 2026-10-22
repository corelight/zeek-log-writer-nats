#pragma once

#include <nats/nats.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

// Go'ish result type
using Result = std::tuple<bool, std::optional<std::string>>;

inline Result Ok() { return Result{true, std::nullopt}; }
inline Result Error(std::string msg) { return {false, std::move(msg)}; }


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

    /**
     * The epoch is an increasing counter for when the underlying connection has changed.
     *
     * It starts with 0, meaning unconnected and increases with each new reconnection.
     */
    uint64_t Epoch() { return epoch; }

    static std::shared_ptr<Connection> Create(ConnectionSharingPolicy policy, ConnectionOptions opts);

protected:
    ConnectionOptions opts;
    natsConnection* natsConn = nullptr;

    // Deleted in closed_cb(), set in StartConnect()
    std::shared_ptr<CallbackState> cb_state;

private:
    std::atomic<uint64_t> epoch{0};
    static std::mutex connections_mtx;
    static std::map<std::string, std::weak_ptr<Connection>> connections;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
