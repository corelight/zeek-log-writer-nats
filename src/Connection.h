#pragma once

#include <fast_publish.h>
#include <nats/nats.h>
#include <nats/status.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

// Go'ish result type
using Result = std::tuple<bool, natsStatus, std::optional<std::string>>;

inline Result Ok() { return Result{true, NATS_OK, std::nullopt}; }
inline Result Error(natsStatus status, std::string msg) { return {false, status, std::move(msg)}; }

/**
 * Sharing policy for ConnectionFactory::Create()
 */
enum class ConnectionSharingPolicy {
    EXCLUSIVE,
    SHARED,
};

/**
 * How batching should be done.
 */
enum class FastPublishBatchPolicy : uint8_t {
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


/**
 * Options for a fast ingest publisher.
 */
struct FastPublisherOptions {
    size_t max_batch_size;
    uint16_t flow;
    uint16_t max_outstanding_acks;
    int64_t commit_timeout_ms;
    int64_t idle_timeout_ms = 1000;
    bool continue_on_gap = true;
};


class Connection;
class FastPublisher;
using FastPublisherPtr = std::shared_ptr<FastPublisher>;

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
class Connection : public std::enable_shared_from_this<Connection> {
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

    /**
     * Publish the given low-level message on the underlying natsConnection.
     */
    Result Publish(natsMsg* msg);

    /**
     * @return pointer to underlying natsConnection.
     */
    natsConnection* RawConnection() { return natsConn; }


    FastPublisherPtr CreateFastPublisher(FastPublishBatchPolicy policy, FastPublisherOptions opts);

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
    std::atomic<uint64_t> epoch{0};
    static std::mutex connections_mtx;
    static std::map<std::string, std::weak_ptr<Connection>> connections;

    FastPublisherPtr shared_publisher;
};

/**
 * A fast publish batch that commits when full.
 */
class FastPublisher {
public:
    FastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts);
    virtual ~FastPublisher();

    // TODO: Check this is the common pattern.
    FastPublisher(const FastPublisher& o) = delete;
    FastPublisher(FastPublisher&& o) = delete;
    FastPublisher operator=(FastPublisher& o) = delete;
    FastPublisher operator=(FastPublisher&& o) = delete;

    /**
     * Creates a new batch if needed, may be blocking, may commit.
     */
    Result AddMsg(natsMsg* msg) {
        /*blub*/
        return DoAddMsg(msg, /*subject=*/nullptr, /*data=*/nullptr, /*data_len=*/0);
    }

    /**
     * Creates a new batch if needed, may be blocking, may commit.
     *
     * This can be faster than AddMsg() taking a natsMsg because
     * it avoids an intermediate natsMsg creation. But it also means
     * you cannot set any headers.
     */
    Result AddMsg(const char* subject, const void* data, int data_len) {
        return DoAddMsg(/*msg=*/nullptr, subject, data, data_len);
    }

    /**
     * Commit the batch even if it's not full.
     */
    virtual Result Commit();

    bool IsIdle() const {
        // Meh, not sure this is great.
        return (nats_Now() - idle_ts) > opts.idle_timeout_ms;
    }

    /**
     * @return The current batch_size. May be pretty large for unlimited batches.
     */
    size_t BatchSize() const { return batch_size; }

    /**
     * Error Callbacks.
     */
    void ErrorHandler(natsStatus status, const char* description);

protected:
    virtual Result DoAddMsg(natsMsg* msg, const char* subject, const void* data, int data_len);

    std::shared_ptr<Connection> conn;
    FastPublisherOptions opts;
    jsFastPublishCtx* fp_ctx = nullptr;

    // Make those atomic so that reading isn't upsetting TSAN.
    std::atomic<size_t> batch_size = 0;
    std::atomic<int64_t> idle_ts = 0;
};

/**
 * The shared fast publisher will have all threads calling AddMsg() in fast
 * succession and lock. It'll probably suck though it should be fast compared
 * to the underlying IO and stalling,.
 * We can also extend to a locked AddMsgs(std::span<natsMsg*> msgs)
 * if we're okay patching upstream Zeek (I think we should, it makes sense).
 *
 * TODO: Find a way to report metrics back. Maybe AddMsg() could take
 *       a pointer to WriterStats similar to #25?
 */
class SharedFastPublisher : public FastPublisher {
public:
    SharedFastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts);

    Result DoAddMsg(natsMsg* msg, const char* subject, const void* data, int data_len) override {
        std::scoped_lock lock{mtx};
        return FastPublisher::DoAddMsg(msg, subject, data, data_len);
    }

    Result Commit() override {
        std::scoped_lock lock{mtx};
        return FastPublisher::Commit();
    }

private:
    std::mutex mtx;
};
} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
