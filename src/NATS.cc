#include "NATS.h"

#include <nats/nats.h>
#include <cstdio>
#include <mutex>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/logging/WriterFrontend.h"
#include "zeek/telemetry/Manager.h"

#include "Connection.h"
#include "Plugin.h"

using namespace zeek::logging;
using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSWriter::NATSWriter(WriterFrontend* frontend) : WriterBackend(frontend, /*send_heartbeats=*/false) {
    // Initialize the NATS metrics with callbacks that use
    // the embedded WriterStats in in a NATSWriter instance.
    std::vector<telemetry::LabelView> labels = {{"filter-name", frontend->GetFilterName()},
                                                {"path", frontend->Info().path}};

    dropped_writes_total = zeek::telemetry_mgr->CounterInstance(
        "zeek", "nats-log-writer-backend-dropped-writes", labels,
        "Dropped log writes of the NATS log writer because of connectivity issues or other problems.", "",
        [stats = &writer_stats]() { return static_cast<double>(stats->dropped_writes); }),

    publish_errors_total =
        zeek::telemetry_mgr
            ->CounterInstance("zeek", "nats-log-writer-backend-publish-errors", labels,
                              "Publish errors reported from the NATS server via the installed AckHandler", "",
                              [stats = &writer_stats]() { return static_cast<double>(stats->publish_errors); }),

    publish_timeouts_total =
        zeek::telemetry_mgr
            ->CounterInstance("zeek", "nats-log-writer-backend-publish-timeouts", labels,
                              "Publish timeouts when publish_async_max_wait or publish_async_stall_wait_ms were hit",
                              "", [stats = &writer_stats]() { return static_cast<double>(stats->publish_timeouts); }),

    publish_acks_total =
        zeek::telemetry_mgr->CounterInstance("zeek", "nats-log-writer-backend-publish-acks", labels,
                                             "Publish acknowledgements reported via the installed AckHandler", "",
                                             [stats = &writer_stats]() {
                                                 return static_cast<double>(stats->publish_acks);
                                             });

    // Read script-layer globals on the main thread. DoInit runs in the writer
    // backend thread where global_scope() is not safe to access.
    url = zeek::id::find_val<zeek::StringVal>("LogNATS::url")->ToStdString();
    conn_sharing_policy = zeek::obj_desc_short(zeek::id::find_val("LogNATS::connection_sharing_policy").get());
    publish_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::publish_subject_template")->ToStdString();
    stream_name_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_name_template")->ToStdString();
    stream_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_subject_template")->ToStdString();
    stream_storage = zeek::id::find_val("LogNATS::stream_storage")->AsEnum();
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
    publish_async_complete_max_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_complete_max_wait")->AsInterval() * 1000);
    connection_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::connection_timeout")->AsInterval() * 1000);
    ping_interval_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::ping_interval")->AsInterval() * 1000);
    reconnect_wait_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::reconnect_wait")->AsInterval() * 1000);
    jitter_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::jitter")->AsInterval() * 1000);
    jitter_tls_ms = static_cast<int64_t>(zeek::id::find_val("LogNATS::jitter_tls")->AsInterval() * 1000);
}

NATSWriter::~NATSWriter() {
    debug("destructor");

    if ( js )
        jsCtx_Destroy(js);

    conn = nullptr;

    // The counter instances outlive the NATSWriter, but the callbacks
    // point at the embedded writer_stats, so ensure to remove them.
    dropped_writes_total->RemoveCallback();
    publish_errors_total->RemoveCallback();
    publish_timeouts_total->RemoveCallback();
    publish_acks_total->RemoveCallback();
}

namespace {
void _jsPubAck(jsCtx* js, natsMsg* msg, jsPubAck* pa, jsPubAckErr* pae, void* closure) {
    auto* writer = static_cast<NATSWriter*>(closure);

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
    ++writer_stats.publish_acks;
}

void NATSWriter::PublishError(natsStatus err, int js_err, const char* text) {
    // May be called asynchronously and from DoWrite(), so don't use
    // Error() or Fmt() and instead go through fprintf and use a lock.
    static std::mutex mx;
    std::lock_guard lock(mx);
    if ( publish_error_log > 0 ) {
        if ( writer_stats.publish_errors % publish_error_log == 0 ) {
            const char* err_text = natsStatus_GetText(err);
            eprintf("%s: PublishError: %s [pid=%d err=%d err_text=%s js_err=%d publish_errors=%" PRIu64 "]\n", Name(),
                    text ? text : "<null>", getpid(), err, err_text ? err_text : "<null>", js_err,
                    writer_stats.publish_errors + 1);
        }
    }

    writer_stats.publish_errors++;

    // Track timeouts as a separate metric.
    if ( err == NATS_TIMEOUT )
        writer_stats.publish_timeouts++;
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

    ConnectionOptions conn_opts{
        .url = url,
        .connection_timeout_ms = connection_timeout_ms,
        .ping_interval_ms = ping_interval_ms,
        .reconnect_wait_ms = reconnect_wait_ms,
        .jitter_ms = jitter_ms,
        .jitter_tls_ms = jitter_tls_ms,
    };

    // Create will start connection establishment!
    conn = Connection::Create(sharing_policy, conn_opts);

    return true;
}

// This only ensures that the js instance exists!
bool NATSWriter::Connect() {
    if ( js )
        return true;

    debug("Creating a JetStream instance!");
    auto [ok, error] = conn->JetStream(&js, publish_async_max_pending, publish_async_stall_wait_ms, _jsPubAck, this);
    if ( ! ok ) {
        // XXX: This is noisy!
        eprintf("Failed to initialize JetStream: %s", error->c_str());
        return false;
    }

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

    // Add the stream,
    if ( s = js_AddStream(nullptr, js, &cfg, NULL, &jerr); s != NATS_OK ) {
        eprintf("Failed to add stream (stream_name=%s stream_subject=%s): %s", stream_name.c_str(),
                stream_subject.c_str(), nats_GetLastError(nullptr));
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
        if ( dropped_writes_log > 0 && writer_stats.dropped_writes % dropped_writes_log == 0 )
            eprintf("%s: Dropped writes [pid=%d dropped_writes=%" PRIu64 "]\n", Info().path, getpid(),
                    writer_stats.dropped_writes + 1);

        writer_stats.dropped_writes++;
        return true;
    }

    desc.Clear();
    if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
        return false;

    const char* data = (const char*)desc.Bytes();
    int data_len = desc.Size();

    natsMsg* msg;
    if ( s = natsMsg_Create(&msg, publish_subject.c_str(), nullptr /*reply*/, data, data_len); s != NATS_OK ) {
        eprintf("Failed Create message: %s", nats_GetLastError(nullptr));
        return false;
    }

    jsPubOptions opts;
    jsPubOptions_Init(&opts);
    opts.MaxWait = publish_async_max_wait_ms;

    if ( s = js_PublishMsgAsync(js, &msg, &opts); s != NATS_OK )
        PublishError(s, /*js_err=*/0, nats_GetLastError(nullptr));

    natsMsg_Destroy(msg);

    return true;
}

bool NATSWriter::DoRotate(const char* rotated_path, double open, double close, bool terminating) {
    debug("DoRotate");
    FinishedRotation();
    return true;
}

bool NATSWriter::DoFlush(double network_time) {
    debug("DoFlush");
    return true;
}

bool NATSWriter::DoFinish(double network_time) {
    debug("DoFinish");

    if ( ! js ) {
        conn = nullptr; // make sure the connection is released.
        return true;
    }

    natsStatus s = NATS_OK;
    jsPubOptions completeOpts;
    jsPubOptions_Init(&completeOpts);
    completeOpts.MaxWait = publish_async_complete_max_wait_ms;

    if ( s = js_PublishAsyncComplete(js, &completeOpts); s != NATS_OK ) {
        eprintf("DoFinish: PublishAsyncComplete failed: %s", nats_GetLastError(nullptr));

        // Try to get the pending messages. Soelely for reporting any
        // information we can figure out or if it'll fail.
        natsMsgList pending;
        if ( s = js_PublishAsyncGetPendingList(&pending, js); s == NATS_OK ) {
            eprintf("DoFinish: Had %d pending messages", pending.Count);
            writer_stats.dropped_writes += pending.Count;

            natsMsgList_Destroy(&pending);
        }
        else {
            eprintf("DoFinish: js_PublishAsyncGetPendingList() failed: %s", nats_GetLastError(nullptr));
        }
    }

    jsCtx_Destroy(js);
    js = nullptr;

    debug("JetStream context destroyed!");

    return true;
}

bool NATSWriter::DoHeartbeat(double network_time, double current_time) {
    // NOTE: WriterBackend takes send_heartbeats as false, so this isn't running!
    debug("DoHeartbeat");
    return true;
}
