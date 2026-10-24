#include "NATS.h"

#include <nats/nats.h>
#include <nats/version.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/logging/WriterFrontend.h"
#include "zeek/telemetry/Manager.h"

#include "Connection.h"
#include "Plugin.h"

using namespace zeek::logging;
using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

// jsStreamConfig.AllowBatched was added in libnats 3.14.
#define NATS_HAS_ALLOW_BATCHED (NATS_VERSION_MAJOR > 3 || (NATS_VERSION_MAJOR == 3 && NATS_VERSION_MINOR >= 14))

namespace {
// nats-server uses at most this many messages per fast-ingest flow ack,
// divided across the concurrent batches of a stream (fastBatchInit() and
// checkFlowControl() in server/jetstream_batching.go).
constexpr zeek_uint_t max_fast_ingest_flow = 500;
} // namespace

// Heartbeats publish the writes buffered for fast ingest.
NATSWriter::NATSWriter(WriterFrontend* frontend) : WriterBackend(frontend, /*send_heartbeats=*/true) {
    // Initialize the NATS metrics with callbacks that use the
    // writer_stats of this NATSWriter instance.
    std::vector<telemetry::LabelView> labels = {{"filter-name", frontend->GetFilterName()},
                                                {"path", frontend->Info().path}};

    dropped_writes_total = zeek::telemetry_mgr->CounterInstance(
        "zeek", "nats-log-writer-backend-dropped-writes", labels,
        "Dropped log writes of the NATS log writer because of connectivity issues or other problems.", "",
        [stats = writer_stats]() { return static_cast<double>(stats->dropped_writes); }),

    publish_errors_total =
        zeek::telemetry_mgr
            ->CounterInstance("zeek", "nats-log-writer-backend-publish-errors", labels,
                              "Publish errors reported from the NATS server via the installed AckHandler", "",
                              [stats = writer_stats]() { return static_cast<double>(stats->publish_errors); }),

    publish_timeouts_total =
        zeek::telemetry_mgr
            ->CounterInstance("zeek", "nats-log-writer-backend-publish-timeouts", labels,
                              "Publish timeouts when publish_async_max_wait or publish_async_stall_wait_ms were hit, "
                              "or fast-ingest messages of unknown outcome after fast_ingest_ack_timeout",
                              "", [stats = writer_stats]() { return static_cast<double>(stats->publish_timeouts); }),

    publish_acks_total =
        zeek::telemetry_mgr->CounterInstance("zeek", "nats-log-writer-backend-publish-acks", labels,
                                             "Publish acknowledgements reported via the installed AckHandler", "",
                                             [stats = writer_stats]() {
                                                 return static_cast<double>(stats->publish_acks);
                                             });

    publishes_pending =
        zeek::telemetry_mgr->GaugeInstance("zeek", "nats-log-writer-backend-publishes-pending", labels,
                                           "In-flight publishes neither confirmed nor failed", "",
                                           [stats = writer_stats]() { return static_cast<double>(stats->pending); });

    // Read script-layer globals on the main thread. DoInit runs in the writer
    // backend thread where global_scope() is not safe to access.
    url = zeek::id::find_val<zeek::StringVal>("LogNATS::url")->ToStdString();
    conn_sharing_policy = zeek::obj_desc_short(zeek::id::find_val("LogNATS::connection_sharing_policy").get());
    publish_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::publish_subject_template")->ToStdString();
    stream_name_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_name_template")->ToStdString();
    stream_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_subject_template")->ToStdString();
    stream_storage = zeek::id::find_val("LogNATS::stream_storage")->AsEnum();
    stream_persist_async = zeek::id::find_val<zeek::BoolVal>("LogNATS::stream_persist_async")->AsBool();
    include_unset_fields = zeek::id::find_val<zeek::BoolVal>("LogNATS::include_unset_fields")->AsBool();
    create_stream = zeek::id::find_val<zeek::BoolVal>("LogNATS::create_stream")->AsBool();
    path_escape_policy = zeek::obj_desc_short(zeek::id::find_val("LogNATS::path_escape_policy").get());
    json_timestamps = zeek::obj_desc_short(zeek::id::find_val("LogNATS::json_timestamps").get());
    publish_error_log = zeek::id::find_val("LogNATS::publish_error_log")->AsCount();
    dropped_writes_log = zeek::id::find_val("LogNATS::dropped_writes_log")->AsCount();
    publish_async_max_pending = zeek::id::find_val("LogNATS::publish_async_max_pending")->AsInt();
    publish_async_max_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_max_wait")->AsInterval() * 1000);
    publish_async_stall_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_stall_wait")->AsInterval() * 1000);
    publish_async_no_stall = zeek::id::find_val("LogNATS::publish_async_no_stall")->AsBool();
    publish_async_complete_max_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_complete_max_wait")->AsInterval() * 1000);
    connection_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::connection_timeout")->AsInterval() * 1000);
    ping_interval_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::ping_interval")->AsInterval() * 1000);
    reconnect_wait_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::reconnect_wait")->AsInterval() * 1000);
    jitter_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::jitter")->AsInterval() * 1000);
    jitter_tls_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::jitter_tls")->AsInterval() * 1000);
    publish_mode = zeek::obj_desc_short(zeek::id::find_val("LogNATS::publish_mode").get());
    fast_ingest_flow = zeek::id::find_val("LogNATS::fast_ingest_flow")->AsCount();
    fast_ingest_max_outstanding_acks = zeek::id::find_val("LogNATS::fast_ingest_max_outstanding_acks")->AsCount();
    fast_ingest_writer_batch = zeek::id::find_val("LogNATS::fast_ingest_writer_batch")->AsCount();
    fast_ingest_ack_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_ingest_ack_timeout")->AsInterval() * 1000);
    fast_ingest_continue_on_gap = zeek::id::find_val("LogNATS::fast_ingest_continue_on_gap")->AsBool();
    fast_ingest_idle_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_ingest_idle_timeout")->AsInterval() * 1000);
    fast_ingest_queue_size = zeek::id::find_val("LogNATS::fast_ingest_queue_size")->AsCount();
    fast_ingest_no_stall = zeek::id::find_val("LogNATS::fast_ingest_no_stall")->AsBool();
    fast_ingest_stall_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_ingest_stall_wait")->AsInterval() * 1000);
}

NATSWriter::~NATSWriter() {
    debug("destructor");

#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Without DoFinish(), e.g. when initialization failed.
    if ( fast_batch )
        fast_batch->Release(fast_ingest_ack_timeout_ms);

    fast_batch = nullptr;
#endif

    if ( js )
        jsCtx_Destroy(js);

    conn = nullptr;

    // The counter instances outlive the NATSWriter, so ensure to remove
    // the callbacks referencing its writer_stats.
    dropped_writes_total->RemoveCallback();
    publish_errors_total->RemoveCallback();
    publish_timeouts_total->RemoveCallback();
    publish_acks_total->RemoveCallback();
    publishes_pending->RemoveCallback();
}

namespace {
void _jsPubAck(jsCtx* js, natsMsg* msg, jsPubAck* pa, jsPubAckErr* pae, void* closure) {
    auto* writer = static_cast<NATSWriter*>(closure);

    writer->DecrementPending();

    if ( pa != nullptr ) {
        writer->PublishAck(pa->Stream, pa->Sequence, pa->Domain, pa->Duplicate);
    }
    else if ( pae != nullptr ) {
        writer->PublishError(pae->Err, pae->ErrCode, pae->ErrText);
    }

    natsMsg_Destroy(msg);
}

struct Replace {
    std::string needle;
    std::string replacement;
};

std::string template_replace(std::string tmpl, std::vector<Replace>& replacements) {
    for ( const auto& r : replacements ) {
        size_t offset = 0;
        while ( (offset = tmpl.find(r.needle, offset)) != std::string::npos ) {
            tmpl = tmpl.replace(offset, r.needle.size(), r.replacement);
            offset += r.replacement.size();
        }
    }

    return tmpl;
}

bool is_path_token_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

// Escape a log path so it is a single NATS subject token and a valid stream
// name. Bytes outside [A-Za-z0-9_-] become prefix followed by two lowercase
// hex digits, so paths such as "conn", "dhcp_fp" or "conn-0" are unchanged.
std::string escape_path(const std::string& path, const char* prefix) {
    std::string out;
    out.reserve(path.size());
    for ( unsigned char c : path ) {
        if ( is_path_token_char(c) ) {
            out += static_cast<char>(c);
        }
        else {
            char hex[2];
            zeek::util::bytetohex(c, hex);
            out += prefix;
            out.append(hex, sizeof(hex));
        }
    }

    return out;
}
} // namespace

void NATSWriter::PublishAck(const char* stream, uint64_t sequence, const char* domain, bool duplicate) {
    ++writer_stats->publish_acks;
}

void NATSWriter::PublishError(natsStatus err, int js_err, const char* text, zeek_uint_t n) {
    if ( n == 0 )
        return;

    auto prev_errors = writer_stats->publish_errors.fetch_add(n);
    auto errors = prev_errors + n;

    // Track timeouts as a separate metric.
    if ( err == NATS_TIMEOUT )
        writer_stats->publish_timeouts += n;

    if ( publish_error_log == 0 )
        return;

    // Log the first error and whenever a multiple of publish_error_log is crossed.
    if ( prev_errors == 0 || prev_errors / publish_error_log != errors / publish_error_log ) {
        const char* err_text = natsStatus_GetText(err);
        eprintf("%s: PublishError: %s [pid=%d err=%d text=%s js_err=%d publish_errors=%" PRIu64 "]", Info().path,
                text ? text : "<null>", getpid(), err, err_text ? err_text : "<null>", js_err, errors);
    }
}


void NATSWriter::DropWrite(natsStatus err, const char* text, zeek_uint_t n) {
    if ( n == 0 )
        return;

    auto prev_dropped_writes = writer_stats->dropped_writes.fetch_add(n);
    auto dropped_writes = prev_dropped_writes + n;

    if ( dropped_writes_log == 0 )
        return;

    // Log the first drop and whenever a multiple of dropped_writes_log is crossed.
    if ( prev_dropped_writes == 0 || prev_dropped_writes / dropped_writes_log != dropped_writes / dropped_writes_log )
        eprintf("%s: Dropped writes [pid=%d err=%d text=%s dropped_writes=%" PRIu64 "]", Info().path, getpid(), err,
                text, dropped_writes);
}

bool NATSWriter::DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) {
    debug("DoInit %s", info.path);
    natsStatus s = NATS_OK;

    for ( const auto& [name, value] : info.config ) {
        if ( zeek::util::streq(name, "url") ) {
            url = value;
        }
        else if ( zeek::util::streq(name, "stream_name_template") ) {
            stream_name_template = value;
        }
        else if ( zeek::util::streq(name, "stream_subject_template") ) {
            stream_subject_template = value;
        }
        else if ( zeek::util::streq(name, "publish_subject_template") ) {
            publish_subject_template = value;
        }
        else if ( zeek::util::streq(name, "json_timestamps") ) {
            json_timestamps = value;
        }
        else if ( zeek::util::streq(name, "path_escape_policy") ) {
            path_escape_policy = value;
        }
        else if ( zeek::util::streq(name, "include_unset_fields") ) {
            if ( zeek::util::streq(value, "T") ) {
                include_unset_fields = true;
            }
            else if ( zeek::util::streq(value, "F") ) {
                include_unset_fields = false;
            }
            else {
                eprintf("Unknown value for include_unset_fields %s:%s", name, value);
                return false;
            }
        }
        else if ( zeek::util::streq(name, "create_stream") ) {
            if ( zeek::util::streq(value, "T") ) {
                create_stream = true;
            }
            else if ( zeek::util::streq(value, "F") ) {
                create_stream = false;
            }
            else {
                eprintf("Unknown value for create_stream %s:%s", name, value);
                return false;
            }
        }
        else if ( zeek::util::streq(name, "connection_sharing_policy") ) {
            conn_sharing_policy = value;
        }
        else if ( zeek::util::streq(name, "publish_mode") ) {
            publish_mode = value;
        }
        else {
            eprintf("Unknown map config %s", name);
            return false;
        }
    }

    std::string path;
    if ( path_escape_policy == "LogNATS::ESCAPE_POLICY_NONE" ) {
        path = info.path;
    }
    else if ( path_escape_policy == "LogNATS::ESCAPE_POLICY_PERCENT" ) {
        path = escape_path(info.path, "%");
    }
    else if ( path_escape_policy == "LogNATS::ESCAPE_POLICY_HEX" ) {
        path = escape_path(info.path, "\\x");
    }
    else {
        eprintf("Invalid path_escape_policy %s", path_escape_policy.c_str());
        return false;
    }

    std::vector<Replace> replacements({{"{path}", path}});

    stream_name = template_replace(stream_name_template, replacements);
    publish_subject = template_replace(publish_subject_template, replacements);
    stream_subject = template_replace(stream_subject_template, replacements);
    stream_subjects.push_back(stream_subject.c_str());

    debug("Templated: stream_name=%s subject=%s stream_subject=%s", stream_name.c_str(), publish_subject.c_str(),
          stream_subject.c_str());

    zeek::threading::formatter::JSON::TimeFormat tf;
    if ( json_timestamps == "JSON::TS_EPOCH" ) {
        tf = zeek::threading::formatter::JSON::TS_EPOCH;
    }
    else if ( json_timestamps == "JSON::TS_MILLIS" ) {
        tf = zeek::threading::formatter::JSON::TS_MILLIS;
    }
    else if ( json_timestamps == "JSON::TS_MILLIS_UNSIGNED" ) {
        tf = zeek::threading::formatter::JSON::TS_MILLIS_UNSIGNED;
    }
    else if ( json_timestamps == "JSON::TS_ISO8601" ) {
        tf = zeek::threading::formatter::JSON::TS_ISO8601;
    }
    else {
        eprintf("Invalid json_timestamps format %s", json_timestamps.c_str());
        return false;
    }
    formatter = std::make_unique<zeek::threading::formatter::JSON>(this, tf, include_unset_fields);

    ConnectionSharingPolicy sharing_policy;
    if ( conn_sharing_policy == "LogNATS::CONNECTION_EXCLUSIVE" ) {
        sharing_policy = ConnectionSharingPolicy::EXCLUSIVE;
    }
    else if ( conn_sharing_policy == "LogNATS::CONNECTION_SHARED" ) {
        sharing_policy = ConnectionSharingPolicy::SHARED;
    }
    else {
        eprintf("Invalid connection sharing policy: %s", conn_sharing_policy.c_str());
        return false;
    }

    if ( publish_mode == "LogNATS::PUBLISH_ASYNC" ) {
        mode = PublishMode::ASYNC;
    }
    else if ( publish_mode == "LogNATS::PUBLISH_FAST_INGEST" ) {
#ifdef HAVE_ORBIT_FAST_PUBLISH
        mode = PublishMode::FAST_INGEST;

        if ( fast_ingest_flow < 1 || fast_ingest_flow > UINT16_MAX ) {
            eprintf("Invalid fast_ingest_flow %" PRIu64 " (1-%u)", fast_ingest_flow, UINT16_MAX);
            return false;
        }

        // The server never acknowledges less often than every 500 messages.
        if ( fast_ingest_flow > max_fast_ingest_flow ) {
            static std::once_flag warned;
            std::call_once(warned, [this]() {
                eprintf("fast_ingest_flow %" PRIu64 " exceeds the server's maximum, using %" PRIu64, fast_ingest_flow,
                        max_fast_ingest_flow);
            });

            fast_ingest_flow = max_fast_ingest_flow;
        }

        // ADR-50: Clients must not allow more than 3 outstanding acks.
        if ( fast_ingest_max_outstanding_acks < 1 || fast_ingest_max_outstanding_acks > 3 ) {
            eprintf("Invalid fast_ingest_max_outstanding_acks %" PRIu64 " (1-3)", fast_ingest_max_outstanding_acks);
            return false;
        }

        if ( fast_ingest_ack_timeout_ms <= 0 ) {
            eprintf("Invalid fast_ingest_ack_timeout %" PRId64 "ms", fast_ingest_ack_timeout_ms);
            return false;
        }

        if ( fast_ingest_writer_batch < 1 ) {
            eprintf("Invalid fast_ingest_writer_batch %" PRIu64 " (>= 1)", fast_ingest_writer_batch);
            return false;
        }

        if ( fast_ingest_queue_size < 1 ) {
            eprintf("Invalid fast_ingest_queue_size %" PRIu64 " (>= 1)", fast_ingest_queue_size);
            return false;
        }

        if ( fast_ingest_stall_wait_ms < 0 ) {
            eprintf("Invalid fast_ingest_stall_wait %" PRId64 "ms", fast_ingest_stall_wait_ms);
            return false;
        }

#if ! NATS_HAS_ALLOW_BATCHED
        if ( create_stream ) {
            eprintf("create_stream with PUBLISH_FAST_INGEST requires libnats 3.14 or later (have %s)",
                    NATS_VERSION_STRING);
            return false;
        }
#endif
#else
        eprintf("PUBLISH_FAST_INGEST is not supported, the plugin was built without orbit.c fast publish support");
        return false;
#endif
    }
    else {
        eprintf("Invalid publish_mode: %s", publish_mode.c_str());
        return false;
    }

    ConnectionOptions conn_opts{
        .url = url,
        .connection_timeout_ms = connection_timeout_ms,
        .ping_interval_ms = ping_interval_ms,
        .reconnect_wait_ms = reconnect_wait_ms,
        .jitter_ms = jitter_ms,
        .jitter_tls_ms = jitter_tls_ms,
    };

    // Create will start connection establishment!
    auto [ok, tmp_conn, error] = Connection::Create(sharing_policy, conn_opts);

    if ( ! ok ) {
        Error(Fmt("Connection::Create() failed: %s", error->c_str()));
        return false;
    }

    conn = std::move(tmp_conn);
    return true;
}

// This only ensures that the js instance exists!
bool NATSWriter::Connect() {
    if ( js )
        return true;

    debug("Creating a JetStream instance!");
    auto [ok, status, error] =
        conn->JetStream(&js, publish_async_max_pending, publish_async_stall_wait_ms, _jsPubAck, this);
    if ( ! ok )
        return false;

    debug("JetStream context created!");

    if ( ! create_stream )
        return true;

    natsStatus s;
    jsErrCode jerr;
    jsStreamConfig cfg;

    jsStreamConfig_Init(&cfg);
    cfg.Name = stream_name.c_str();
    // Set the subject
    cfg.Subjects = (const char**)stream_subjects.data();
    cfg.SubjectsLen = 1;
    // XXX: Fix magic numbers.
    if ( stream_storage == 0 ) {
        debug("Using file storage");
        cfg.Storage = js_FileStorage;
    }
    else {
        debug("Using memory storage");
        cfg.Storage = js_MemoryStorage;
    }

#if NATS_HAS_ALLOW_BATCHED
    // Acknowledge before the message is flushed to storage.
    if ( stream_persist_async )
        cfg.PersistMode = js_PersistAsync;

    // Fast-ingest batches are rejected by streams without allow_batched.
    if ( mode == PublishMode::FAST_INGEST )
        cfg.AllowBatched = true;
#endif

    // Add the stream,
    if ( s = js_AddStream(nullptr, js, &cfg, NULL, &jerr); s != NATS_OK ) {
        eprintf("Failed to add stream (stream_name=%s stream_subject=%s): %s", stream_name.c_str(),
                stream_subject.c_str(), LastError(s));
        jsCtx_Destroy(js);
        js = nullptr;
        return false;
    }

    debug("Stream added!");

    return true;
}

bool NATSWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;
    jsErrCode jerr;

    if ( ! Connect() ) {
        DropWrite(NATS_NOT_YET_CONNECTED, "not yet connected in DoWrite()");
        return true;
    }

    if ( mode == PublishMode::ASYNC && MayStall() ) {
        DropWrite(NATS_ERR, "may stall");
        return true;
    }

    desc.Clear();
    if ( ! formatter->Describe(&desc, num_fields, fields, vals) ) {
        DropWrite(NATS_ERR, "formatter describe failed");
        return true;
    }

    const char* data = (const char*)desc.Bytes();
    int data_len = desc.Size();

#ifdef HAVE_ORBIT_FAST_PUBLISH
    if ( mode == PublishMode::FAST_INGEST ) {
        FastIngestWrite(data, data_len);
        return true;
    }
#endif

    natsMsg* msg;
    if ( s = natsMsg_Create(&msg, publish_subject.c_str(), nullptr /*reply*/, data, data_len); s != NATS_OK ) {
        DropWrite(s, "failed to create message");
        return true;
    }

    jsPubOptions opts;
    jsPubOptions_Init(&opts);
    opts.MaxWait = publish_async_max_wait_ms;

    if ( s = js_PublishMsgAsync(js, &msg, &opts); s != NATS_OK )
        PublishError(s, /*js_err=*/0, LastError(s));
    else
        IncrementPending();

    natsMsg_Destroy(msg);

    return true;
}

#ifdef HAVE_ORBIT_FAST_PUBLISH
void NATSWriter::FastIngestWrite(const char* data, int data_len) {
    // Publishing while disconnected would stall for fast_ingest_ack_timeout
    // waiting on flow acks that can't arrive.
    if ( ! conn->IsConnected() ) {
        DropWrite(NATS_CONNECTION_DISCONNECTED, "not connected in DoWrite()");
        return;
    }

    // Buffered writes count as pending, so that at any time every write
    // is acked, failed, timed out, dropped or pending.
    fast_buffered.emplace_back(data, data_len);
    IncrementPending();

    if ( fast_buffered.size() >= fast_ingest_writer_batch )
        FastIngestPublishBuffered();
}

void NATSWriter::FastIngestPublishBuffered() {
    if ( fast_buffered.empty() )
        return;

    if ( ! conn->IsConnected() ) {
        writer_stats->pending -= static_cast<int64_t>(fast_buffered.size());
        DropWrite(NATS_CONNECTION_DISCONNECTED, "not connected when queueing buffered writes", fast_buffered.size());
        fast_buffered.clear();
        return;
    }

    if ( ! fast_batch ) {
        FastBatchConfig cfg{
            .stream = stream_name,
            .flow = static_cast<uint16_t>(fast_ingest_flow),
            .max_outstanding_acks = static_cast<uint16_t>(fast_ingest_max_outstanding_acks),
            .ack_timeout_ms = fast_ingest_ack_timeout_ms,
            .continue_on_gap = fast_ingest_continue_on_gap,
            .idle_timeout_ms = fast_ingest_idle_timeout_ms,
            .queue_bytes = fast_ingest_queue_size,
            .no_stall = fast_ingest_no_stall,
            .stall_wait_ms = fast_ingest_stall_wait_ms,
            .publish_error_log = publish_error_log,
        };

        fast_batch = Connection::AcquireFastBatch(conn, cfg);
        fast_writer = std::make_shared<FastBatchWriter>(FastBatchWriter{
            .path = Info().path,
            .subject = publish_subject,
            .stats = writer_stats,
        });
    }

    if ( size_t dropped = fast_batch->Enqueue(fast_writer, std::move(fast_buffered)); dropped > 0 ) {
        writer_stats->pending -= static_cast<int64_t>(dropped);
        DropWrite(NATS_ERR, "fast-ingest queue full", dropped);
    }

    fast_buffered.clear();
    fast_buffered.reserve(fast_ingest_writer_batch);
}
#endif

bool NATSWriter::DoRotate(const char* rotated_path, double open, double close, bool terminating) {
    debug("DoRotate");
    FinishedRotation();
    return true;
}

bool NATSWriter::DoFlush(double network_time) {
    debug("DoFlush");

#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Commit the shared batch once all writes so far are published, so
    // they're confirmed. Otherwise, the last partial flow window is only
    // acknowledged by later writes. The next write starts a new batch.
    if ( mode == PublishMode::FAST_INGEST ) {
        FastIngestPublishBuffered();

        if ( fast_batch && ! fast_batch->Flush(fast_ingest_ack_timeout_ms) )
            debug("DoFlush: fast-ingest commit timed out");
    }
#endif

    return true;
}

bool NATSWriter::DoFinish(double network_time) {
    debug("DoFinish");

    if ( ! js ) {
        conn = nullptr; // make sure the connection is released.
        return true;
    }

#ifdef HAVE_ORBIT_FAST_PUBLISH
    if ( mode == PublishMode::FAST_INGEST ) {
        FastIngestPublishBuffered();

        if ( fast_batch ) {
            if ( auto n = fast_batch->Finish(fast_writer, publish_async_complete_max_wait_ms); n > 0 )
                eprintf("%s: DoFinish: %" PRIu64 " fast-ingest writes not confirmed in time, counted as dropped",
                        Info().path, n);

            // The last writer of the batch commits it and stops its
            // publisher thread.
            fast_batch->Release(publish_async_complete_max_wait_ms);
            fast_batch = nullptr;
        }

        jsCtx_Destroy(js);
        js = nullptr;

        debug("JetStream context destroyed!");

        return true;
    }
#endif

    natsStatus s = NATS_OK;
    jsPubOptions completeOpts;
    jsPubOptions_Init(&completeOpts);
    completeOpts.MaxWait = publish_async_complete_max_wait_ms;

    if ( s = js_PublishAsyncComplete(js, &completeOpts); s != NATS_OK ) {
        eprintf("%s: DoFinish: PublishAsyncComplete failed: %s", Info().path, LastError(s));

        // Try to get the pending messages. Solely for reporting any
        // information we can figure out or if it'll fail.
        natsMsgList pending;
        if ( s = js_PublishAsyncGetPendingList(&pending, js); s == NATS_OK ) {
            eprintf("%s: DoFinish: Had %d pending messages", Info().path, pending.Count);
            writer_stats->dropped_writes += pending.Count;

            natsMsgList_Destroy(&pending);
        }
        else {
            eprintf("%s: DoFinish: js_PublishAsyncGetPendingList() failed: %s", Info().path, LastError(s));
        }
    }

    jsCtx_Destroy(js);
    js = nullptr;

    debug("JetStream context destroyed!");

    return true;
}

bool NATSWriter::DoHeartbeat(double network_time, double current_time) {
    debug("DoHeartbeat");

#ifdef HAVE_ORBIT_FAST_PUBLISH
    // Bound how long buffered writes of a quiet writer wait.
    if ( mode == PublishMode::FAST_INGEST )
        FastIngestPublishBuffered();
#endif

    return true;
}
