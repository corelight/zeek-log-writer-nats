#pragma once

#include <atomic>
#include <cstdint>

namespace zeek::plugin::Zeek_Log_Writer_NATS::detail {

/**
 * Publish outcomes of a log writer, exposed as metrics.
 *
 * With PUBLISH_FAST_INGEST, the publisher thread of the shared batch
 * updates them, possibly after the writer is gone, so writers hold them
 * through a std::shared_ptr.
 */
struct NATSWriterStats {
    std::atomic<uint64_t> dropped_writes = 0;
    std::atomic<uint64_t> publish_errors = 0;
    std::atomic<uint64_t> publish_acks = 0;
    // With PUBLISH_ASYNC, timeouts are also counted as publish_errors.
    // With PUBLISH_FAST_INGEST, they are messages of unknown outcome
    // (likely stored) and not counted as publish_errors.
    std::atomic<uint64_t> publish_timeouts = 0;
    // Pending publishes that have neither been acked,
    // timed out, or otherwise failed. May go negative,
    // but that's probably a bug. This value is exposed
    // per writer as metric.
    std::atomic<int64_t> pending = 0;
};

} // namespace zeek::plugin::Zeek_Log_Writer_NATS::detail
