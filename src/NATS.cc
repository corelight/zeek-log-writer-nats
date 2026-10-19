#include "NATS.h"

#include <nats/nats.h>
#include <unistd.h>
#include <cinttypes>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/logging/WriterFrontend.h"
#include "zeek/telemetry/Manager.h"

#include "Plugin.h"

using namespace zeek::logging;
using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSWriter::NATSWriter(WriterFrontend* frontend)
    : WriterBackend(frontend), writer_stats(std::make_shared<NATSWriterStats>()) {
    // Initialize the NATS metrics with callbacks that use the
    // writer's stats, which are updated from the shared client's
    // ack handler, too.
    std::vector<telemetry::LabelView> labels = {{"filter-name", frontend->GetFilterName()},
                                                {"path", frontend->Info().path}};

    dropped_writes_total = zeek::telemetry_mgr->CounterInstance(
        "zeek", "nats-log-writer-backend-dropped-writes", labels,
        "Dropped log writes of the NATS log writer because of connectivity issues or other problems.", "",
        [stats = writer_stats.get()]() { return static_cast<double>(stats->dropped_writes); }),

    publish_errors_total =
        zeek::telemetry_mgr
            ->CounterInstance("zeek", "nats-log-writer-backend-publish-errors", labels,
                              "Publish errors reported from the NATS server via the installed AckHandler", "",
                              [stats = writer_stats.get()]() { return static_cast<double>(stats->publish_errors); }),

    publish_acks_total =
        zeek::telemetry_mgr->CounterInstance("zeek", "nats-log-writer-backend-publish-acks", labels,
                                             "Publish acknowledgements reported via the installed AckHandler", "",
                                             [stats = writer_stats.get()]() {
                                                 return static_cast<double>(stats->publish_acks);
                                             });

    // Read script-layer globals on the main thread. DoInit runs in the writer
    // backend thread where global_scope() is not safe to access.
    url = zeek::id::find_val<zeek::StringVal>("LogNATS::url")->ToStdString();
    publish_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::publish_subject_template")->ToStdString();
    stream_name_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_name_template")->ToStdString();
    stream_subject_template = zeek::id::find_val<zeek::StringVal>("LogNATS::stream_subject_template")->ToStdString();
    stream_storage = zeek::id::find_val("LogNATS::stream_storage")->AsEnum();
    include_unset_fields = zeek::id::find_val<zeek::BoolVal>("LogNATS::include_unset_fields")->AsBool();
    create_stream = zeek::id::find_val<zeek::BoolVal>("LogNATS::create_stream")->AsBool();
    json_timestamps = zeek::obj_desc_short(zeek::id::find_val("LogNATS::json_timestamps").get());
    writer_stats->publish_error_log = zeek::id::find_val("LogNATS::publish_error_log")->AsCount();
    dropped_writes_log = zeek::id::find_val("LogNATS::dropped_writes_log")->AsCount();
    share_connection = zeek::id::find_val<zeek::BoolVal>("LogNATS::share_connection")->AsBool();
    publish_async_max_pending = zeek::id::find_val("LogNATS::publish_async_max_pending")->AsInt();
    publish_async_stall_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_stall_wait")->AsInterval() * 1000);
    publish_async_complete_max_wait_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::publish_async_complete_max_wait")->AsInterval() * 1000);
}

NATSWriter::~NATSWriter() {
    debug("destructor");
    if ( client )
        client->UnregisterStats(publish_subject, writer_stats);

    // The counter instances outlive the NATSWriter, but the callbacks
    // point at the embedded writer_stats, so ensure to remove them.
    dropped_writes_total->RemoveCallback();
    publish_acks_total->RemoveCallback();
    publish_errors_total->RemoveCallback();
}

namespace {
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
} // namespace

bool NATSWriter::DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) {
    debug("DoInit %s", info.path);

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
        else if ( zeek::util::streq(name, "include_unset_fields") ) {
            if ( zeek::util::streq(value, "T") ) {
                include_unset_fields = true;
            }
            else if ( zeek::util::streq(value, "F") ) {
                include_unset_fields = false;
            }
            else {
                Error(Fmt("NATS: Unknown value for include_unset_fields %s:%s", name, value));
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
                Error(Fmt("NATS: Unknown value for create_stream %s:%s", name, value));
                return false;
            }
        }
        else {
            Error(Fmt("NATS: Unknown map config %s", name));
            return false;
        }
    }

    std::vector<Replace> replacements({{"{path}", info.path}});

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
        Error(Fmt("NATS: Invalid json_timestamps format %s", json_timestamps.c_str()));
        return false;
    }
    formatter = std::make_unique<zeek::threading::formatter::JSON>(this, tf, include_unset_fields);

    writer_stats->name = Name();
    client = SharedClient::Acquire({.url = url,
                                    .share_connection = share_connection,
                                    .publish_async_max_pending = publish_async_max_pending,
                                    .publish_async_stall_wait_ms = publish_async_stall_wait_ms});
    client->RegisterStats(publish_subject, writer_stats);

    return true;
}

jsCtx* NATSWriter::Connect() {
    if ( js )
        return js;

    std::string error;
    js = client->JetStream(&error);
    if ( ! js ) {
        if ( ! error.empty() )
            Error(Fmt("NATS: %s", error.c_str()));

        return nullptr;
    }

    if ( ! create_stream || stream_added )
        return js;

    // Only attempt to add the stream once. If it fails, keep publishing
    // anyway, the stream may be created or fixed up externally later.
    stream_added = true;

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
    if ( natsStatus s = js_AddStream(nullptr, js, &cfg, NULL, &jerr); s != NATS_OK ) {
        Error(Fmt("NATS: Failed to add stream (stream_name=%s stream_subject=%s): %s", stream_name.c_str(),
                  stream_subject.c_str(), nats_GetLastError(nullptr)));
        return js;
    }

    debug("Stream added!");

    return js;
}

void NATSWriter::DroppedWrite() {
    if ( dropped_writes_log > 0 && writer_stats->dropped_writes % dropped_writes_log == 0 )
        Error(Fmt("Dropped writes [pid=%d dropped_writes=%" PRIu64 "]\n", getpid(), writer_stats->dropped_writes + 1));

    writer_stats->dropped_writes++;
}

bool NATSWriter::SkipStalledPublish() {
    if ( ! stalled )
        return false;

    // Once the server responds again, publish as usual.
    if ( client->Responses() != stalled_responses ) {
        stalled = false;
        return false;
    }

    // Otherwise, drop writes rather than having each of them wait for
    // publish_async_stall_wait, e.g. when Zeek flushes logs at shutdown
    // while the server is unavailable. Still attempt a publish now and
    // then in case the pending messages never get a response.
    constexpr auto stalled_publish_interval = std::chrono::seconds(1);
    return std::chrono::steady_clock::now() - last_stalled_publish < stalled_publish_interval;
}

bool NATSWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;
    jsErrCode jerr;

    if ( ! Connect() ) {
        DroppedWrite();
        return true;
    }

    if ( SkipStalledPublish() ) {
        DroppedWrite();
        return true;
    }

    desc.Clear();
    if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
        return false;

    const char* data = (const char*)desc.Bytes();
    int data_len = desc.Size();

    natsMsg* msg;
    if ( s = natsMsg_Create(&msg, publish_subject.c_str(), nullptr /*reply*/, data, data_len); s != NATS_OK ) {
        Error(Fmt("NATS: Failed Create message: %s", nats_GetLastError(nullptr)));
        return false;
    }

    if ( s = js_PublishMsgAsync(js, &msg, NULL); s == NATS_OK ) {
        stalled = false;
    }
    else {
        // NATS_TIMEOUT means publish_async_max_pending messages were
        // in flight for longer than publish_async_stall_wait.
        if ( s == NATS_TIMEOUT ) {
            stalled = true;
            stalled_responses = client->Responses();
            last_stalled_publish = std::chrono::steady_clock::now();
            DroppedWrite();
        }
        else
            writer_stats->PublishError(s, nats_GetLastError(nullptr));
    }

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
    if ( ! js )
        return true;

    // The JetStream context may be shared with other writers, so this waits
    // for their outstanding publishes, too. This mostly happens during
    // shutdown when all writers finish, so that seems acceptable.
    natsStatus s = NATS_OK;
    jsPubOptions completeOpts;
    jsPubOptions_Init(&completeOpts);
    completeOpts.MaxWait = publish_async_complete_max_wait_ms;

    if ( s = js_PublishAsyncComplete(js, &completeOpts); s != NATS_OK )
        Warning(Fmt("DoFinish: PublishAsyncComplete failed: %s", nats_GetLastError(nullptr)));

    return true;
}

bool NATSWriter::DoHeartbeat(double network_time, double current_time) {
    debug("DoHeartbeat");
    return true;
}
