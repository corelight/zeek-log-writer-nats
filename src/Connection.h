#pragma once

#include <nats/nats.h>
#include <nats/status.h>
#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <tuple>

// From fast_publish.h
struct __jsFastPublishCtx;
typedef __jsFastPublishCtx jsFastPublishCtx;

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

// Go'ish result type
using Result = std::tuple<bool, natsStatus, std::optional<std::string>>;

inline Result Ok() { return Result{true, NATS_OK, std::nullopt}; }
inline Result Error(natsStatus status, std::string msg) { return {false, status, std::move(msg)}; }

/**
 * Connection sharing policy.
 */
enum class ConnectionSharingPolicy {
    EXCLUSIVE,
    SHARED,
};


/**
 * Fast-ingest batch sharing policy.
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
    uint16_t flow;
    uint16_t max_outstanding_acks;
    int64_t commit_timeout_ms;
    int64_t ack_timeout_ms;
    int64_t idle_timeout_ms = 5000;

    // For now, always fail the batch on a gap!
    bool continue_on_gap = false;
};


class Connection;
class FastPublisher;
class SharedFastPublisher;

using FastPublisherPtr = std::shared_ptr<FastPublisher>;
using SharedFastPublisherPtr = std::shared_ptr<SharedFastPublisher>;

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
     * Whether this connection is currently connected.
     *
     * Used to circuit break;
     */
    bool IsConnected() const { return is_connected; }

    /**
     * Publish the given low-level message on the underlying natsConnection.
     */
    Result Publish(natsMsg* msg);

    /**
     * @return pointer to underlying natsConnection.
     */
    natsConnection* RawConnection() { return natsConn; }

    /**
     * Instantiate or reuse a FastPublisher instance of the given policy.
     */
    FastPublisherPtr GetFastPublisher(FastPublishBatchPolicy policy, FastPublisherOptions opts);

    /**
     * Hand back a fast publisher instance acquired with Get()
     *
     * Mostly interesting for the shared policy: Once all writer
     * threads returned their fast publisher, the connection will
     * ensure the batch is closed.
     */
    void PutFastPublisher(FastPublisherPtr&& fast_publisher);

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
    std::atomic<bool> is_connected{false};

    static std::mutex connections_mtx;
    static std::map<std::string, std::weak_ptr<Connection>> connections;

    FastPublisherPtr shared_publisher;
};

/**
 * A fast-ingest publisher.
 */
class FastPublisher {
public:
    FastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts);

    FastPublisher(const FastPublisher&) = delete;
    FastPublisher(FastPublisher&&) = delete;
    FastPublisher& operator=(FastPublisher&&) = delete;
    FastPublisher& operator=(const FastPublisher&) = delete;

    virtual ~FastPublisher();

    /**
     * Callback to update metrics on the log writer side.
     */
    struct CompletionInfo {
        natsStatus nats_status; // NATS status if available
        uint64_t acked;         // positively confirmed by the server
        uint64_t dropped;       // actively dropped because not connected
        uint64_t failed;        // failed, server error, timeout, ...
    };

    /**
     * Callback passed to AddMsgs()
     */
    using CompletionCallback = std::function<void(CompletionInfo info)>;

    /**
     * Submit all buffers in the provided span as messages at once,
     * invoke ccb for completion once all messages have been acked
     * by the server. In case of early dropping or failures, ccb is
     * invoked with dropped or failed set on the struct.
     *
     * @param subject
     * @param msgs
     * @param ccb
     */
    virtual Result AddMsgs(const char* subject, std::span<std::span<const char>> msgs, CompletionCallback ccb) {
        auto result = AddMsgsImpl(subject, msgs, ccb);
        auto ok = std::get<0>(result);
        if ( ! ok )
            CloseBatchImpl(/*commit=*/false);

        return result;
    }

    /**
     * Close the batch that was opened with AddMsgs(), if any.
     */
    virtual Result CloseBatch(bool commit = true) {
        // Delegate.
        return CloseBatchImpl(commit);
    }

    /**
     * @return true if the batch has been idle for idle_timeout_ms
     * as provided in the options.
     */
    virtual bool IsIdle() const { return IsIdleImpl(); }

    /**
     * Error Callbacks.
     */
    void ErrorHandler(natsStatus status, const char* description);

protected:
    /**
     * AddMsgsImpl doesn't lock and doesn't close a batch if it fails.
     *
     * Call CloseBatchImpl() if this returns an error.
     *
     */
    Result AddMsgsImpl(const char* subject, std::span<std::span<const char>> msgs, CompletionCallback ccb);

    /**
     * Closes an open batch.
     *
     * After this, fp_ctx will be nil and the pending completion callbacks
     * invoked with whatever the server reported.
     *
     * @param commit If true, attempts to commit the batch before
     *
     */
    Result CloseBatchImpl(bool commit = true);

    /**
     * Just following the pattern. Nothing fancy.
     */
    bool IsIdleImpl() const { return (nats_Now() - idle_ts) > opts.idle_timeout_ms; }

private:
    /**
     * Helper method for walking the pending list based on the last_ack_seq
     * set during DoAddMsgs().
     */
    void ProcessPending();

    /**
     * Helper method reporting everything in pending as failed.
     */
    void FailPending();


    Result OpenBatch();

    std::shared_ptr<Connection> conn;
    FastPublisherOptions opts;
    jsFastPublishCtx* fp_ctx = nullptr;

    // The Conn()->Epoch() value at which fp_ctx was created.
    uint64_t fp_epoch = 0;

    // Make those atomic so that reading isn't upsetting TSAN.
    int64_t idle_ts = 0;

    // Values as received from jsFastPublish_Add()
    uint64_t last_batch_seq = 0;
    uint64_t last_ack_seq = 0;

    /**
     * A data structure holding information about sequence and
     * number of messages submitted via AddMsgs() in one go. Once
     * the server has acked up to (seq + len - 1), invoke
     * completion_callback.
     */
    struct Pending {
        uint64_t seq;
        uint64_t len;

        CompletionCallback completion_callback; // completion callback
    };

    /**
     * List of pending/in-flight messages.
     */
    std::deque<Pending> pending;
};

/**
 * A FastPublisher subclass that locks during AddMsg() such
 * that it can be used concurrently from different threads.
 */
class SharedFastPublisher : public FastPublisher {
public:
    SharedFastPublisher(std::shared_ptr<Connection> conn, FastPublisherOptions opts);

    SharedFastPublisher(const SharedFastPublisher&) = delete;
    SharedFastPublisher(SharedFastPublisher&&) = delete;
    SharedFastPublisher& operator=(SharedFastPublisher&&) = delete;
    SharedFastPublisher& operator=(const SharedFastPublisher&) = delete;

    /**
     * Lock the fast publisher, then add msgs.
     */
    Result AddMsgs(const char* subject, std::span<std::span<const char>> msgs, CompletionCallback ccb) override {
        std::scoped_lock lock{mtx};
        return FastPublisher::AddMsgs(subject, msgs, ccb);
    }

    Result CloseBatch(bool commit = true) override {
        std::scoped_lock lock{mtx};
        return FastPublisher::CloseBatch(commit);
    }

    bool IsIdle() const override {
        std::scoped_lock lock{mtx};
        return FastPublisher::IsIdle();
    }

private:
    mutable std::mutex mtx;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
