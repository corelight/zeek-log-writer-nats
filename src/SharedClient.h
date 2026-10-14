#pragma once

#include <nats/nats.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "zeek/util-types.h"

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

struct NATSWriterStats {
    std::atomic<zeek_uint_t> dropped_writes = 0;
    std::atomic<zeek_uint_t> publish_errors = 0;
    std::atomic<zeek_uint_t> publish_acks = 0;

    // Name of the writer for error messages and the n'th publish error to log.
    std::string name;
    zeek_uint_t publish_error_log = 0;

    // Callback for message delivery errors. May be called asynchronously
    // from the NATS library's threads and from DoWrite().
    void PublishError(int code, const char* text);
};

struct SharedClientOptions {
    std::string url;
    int64_t publish_async_max_pending = 0;
    int64_t publish_async_stall_wait_ms = 0;
};

// A NATS connection and JetStream context shared by all NATS writers
// within a Zeek process that publish to the same URL.
//
// Zeek instantiates one writer per log path, each on its own thread.
// Using a connection per writer means the NATS client's flow control
// for asynchronous publishes (PublishAsync.MaxPending) only applies
// per log path, rather than to the process as a whole.
class SharedClient {
public:
    // Returns the client for the given URL, creating it if needed.
    // The client is destroyed once the last writer releases it.
    static std::shared_ptr<SharedClient> Acquire(const SharedClientOptions& opts);

    // Number of established connections in this process.
    static int64_t Connections() { return connections; }

    explicit SharedClient(SharedClientOptions opts);
    ~SharedClient();

    SharedClient(const SharedClient&) = delete;
    SharedClient& operator=(const SharedClient&) = delete;

    // Returns the JetStream context, connecting first if needed.
    //
    // Returns nullptr if not connected. Only one thread attempts to
    // connect at a time, others wait for its result. Failed attempts
    // are retried with exponential backoff and jitter. If this call attempted to
    // connect and failed, the reason is stored in *error.
    jsCtx* JetStream(std::string* error);

    // Registers the stats object to which acks and errors for messages
    // published on subject are attributed. If multiple writers publish
    // on the same subject, acks and errors are attributed to the first.
    void RegisterStats(const std::string& subject, std::shared_ptr<NATSWriterStats> stats);
    void UnregisterStats(const std::string& subject, const std::shared_ptr<NATSWriterStats>& stats);

    // Callback for message acknowledgements and errors.
    void OnPublishAck(natsMsg* msg, jsPubAck* pa, jsPubAckErr* pae);

private:
    std::shared_ptr<NATSWriterStats> LookupStats(const char* subject);
    std::chrono::steady_clock::duration NextBackoff();

    SharedClientOptions opts;

    std::mutex connect_mtx;
    natsOptions* nats_opts = nullptr;
    natsConnection* conn = nullptr;
    std::atomic<jsCtx*> js = nullptr;
    unsigned int connect_failures = 0;
    std::chrono::steady_clock::time_point next_connect_attempt;
    std::mt19937 rng;

    std::mutex stats_mtx;
    std::map<std::string, std::vector<std::shared_ptr<NATSWriterStats>>, std::less<>> stats_by_subject;

    static std::atomic<int64_t> connections;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
