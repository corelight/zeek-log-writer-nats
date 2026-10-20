#pragma once

#include <nats/nats.h>
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
 * Just a struct with the url for now, but if we ever
 * want to pass more connection options around, this
 * will avoid modifying the signature.
 */
struct ConnectionOptions {
    std::string url;
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

    virtual Result Connect() = 0;

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

protected:
    // Low-level helper create the connection to NATS.
    Result ConnectRaw();

    ConnectionOptions opts;
    natsConnection* natsConn = nullptr;
};


/**
 * Interface to create Connection instances.
 */
class ConnectionFactory {
public:
    virtual ~ConnectionFactory() = default;
    virtual std::shared_ptr<Connection> Create(std::string url) = 0;
};


class ExclusiveConnection : public Connection {
public:
    ExclusiveConnection(ConnectionOptions opts) : Connection(std::move(opts)) {}

    Result Connect() override;
};


class ExclusiveConnectionFactory : public ConnectionFactory {
public:
    virtual std::shared_ptr<Connection> Create(std::string url) override;
};


class SharedConnection : public Connection {
public:
    SharedConnection(ConnectionOptions opts) : Connection(std::move(opts)) {}

    Result Connect() override;

private:
    std::mutex connect_mutex;
};


class SharedConnectionFactory : public ConnectionFactory {
public:
    virtual std::shared_ptr<Connection> Create(std::string url) override;

private:
    std::mutex connections_mtx;
    std::map<std::string, std::weak_ptr<Connection>> connections;
};


extern ExclusiveConnectionFactory factory_exclusive;
extern SharedConnectionFactory factory_shared;
} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
