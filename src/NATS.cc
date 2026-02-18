#include "NATS.h"

#include <cstdio>
#include <mutex>

#include "zeek/ID.h"
#include "zeek/Val.h"

#include "Plugin.h"

using namespace zeek::logging;
using namespace zeek::plugin::Zeek_NATS::detail;

NATSWriter::NATSWriter(WriterFrontend* frontend) : WriterBackend(frontend) {}
NATSWriter::~NATSWriter() {
    debug("destructor");
    if ( opts )
        natsOptions_Destroy(opts);

    if ( conn )
        natsConnection_Destroy(conn);

    if ( js )
        jsCtx_Destroy(js);
}

namespace {
void _jsPubErr(jsCtx* js, jsPubAckErr* pae, void* closure) {
    auto* writer = static_cast<NATSWriter*>(closure);
    writer->PublishError(pae->ErrCode, pae->ErrText);
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
} // namespace

void NATSWriter::PublishError(int code, const char* text) {
    // May be called asynchronously and from DoWrite(), so don't use
    // Error() or Fmt() and instead go through fprintf and use a lock.
    static std::mutex mx;
    std::lock_guard lock(mx);
    if ( publish_error_log > 0 ) {
        if ( writer_stats.publish_errors % publish_error_log == 0 ) {
            std::fprintf(stderr, "NATS/%s: PublishError: %s [pid=%d code=%d publish_errors=%" PRIu64 "]\n", Name(),
                         text, getpid(), code, writer_stats.publish_errors + 1);
        }
    }

    writer_stats.publish_errors++;
}

bool NATSWriter::DoInit(const WriterInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) {
    debug("DoInit %s", info.path);
    natsStatus s = NATS_OK;

    url = zeek::id::find_val<zeek::StringVal>("NATS::url")->ToStdString();
    publish_subject_template = zeek::id::find_val<zeek::StringVal>("NATS::publish_subject_template")->ToStdString();
    stream_name_template = zeek::id::find_val<zeek::StringVal>("NATS::stream_name_template")->ToStdString();
    stream_subject_template = zeek::id::find_val<zeek::StringVal>("NATS::stream_subject_template")->ToStdString();
    stream_storage = zeek::id::find_val<zeek::StringVal>("NATS::stream_storage")->AsEnum();
    include_unset_fields = zeek::id::find_val<BoolVal>("NATS::include_unset_fields")->AsBool();
    publish_error_log = zeek::id::find_val<BoolVal>("NATS::publish_error_log")->AsCount();
    dropped_writes_log = zeek::id::find_val<BoolVal>("NATS::dropped_writes_log")->AsCount();
    publish_async_max_pending = zeek::id::find_val<BoolVal>("NATS::publish_async_max_pending")->AsInt();
    publish_async_stall_wait_ms =
        static_cast<int64_t>(zeek::id::find_val<BoolVal>("NATS::publish_async_stall_wait")->AsInterval() * 1000);
    publish_async_complete_max_wait_ms =
        static_cast<int64_t>(zeek::id::find_val<BoolVal>("NATS::publish_async_complete_max_wait")->AsInterval() * 1000);

    for ( const auto& [name, value] : info.config ) {
        if ( zeek::util::streq(name, "url") ) {
            url = value;
        }
        else if ( zeek::util::streq(name, "stream_name_template") ) {
            stream_name_template = value;
        }
        else if ( zeek::util::streq(name, "stream_subject_template") ) {
            stream_name_template = value;
        }
        else if ( zeek::util::streq(name, "publish_subject_template") ) {
            publish_subject_template = value;
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

    // XXX: Make configurable?
    auto tf = zeek::threading::formatter::JSON::TS_EPOCH;
    formatter = std::make_unique<zeek::threading::formatter::JSON>(this, tf, include_unset_fields);

    if ( s = natsOptions_Create(&opts); s != NATS_OK ) {
        Error("NATS: Could not create options");
        return false;
    }

    if ( s = natsOptions_SetURL(opts, url.c_str()); s != NATS_OK ) {
        Error(Fmt("NATS: Failed to SetURL %s: %s", url.c_str(), nats_GetLastError(nullptr)));
        return false;
    }
    if ( s = jsOptions_Init(&jsOpts); s != NATS_OK ) {
        natsOptions_Destroy(opts);
        Error(Fmt("NATS: Failed to init JetStream options: %s", nats_GetLastError(nullptr)));
        return false;
    }

    jsOpts.PublishAsync.MaxPending = publish_async_max_pending;
    jsOpts.PublishAsync.ErrHandler = _jsPubErr;
    jsOpts.PublishAsync.ErrHandlerClosure = this;
    jsOpts.PublishAsync.StallWait = publish_async_stall_wait_ms;

    return true;
}

bool NATSWriter::Connect() {
    if ( conn )
        return true;

    natsStatus s;
    if ( s = natsConnection_Connect(&conn, opts); s != NATS_OK ) {
        Error(Fmt("NATS: Failed to connect to %s: %s", url.c_str(), nats_GetLastError(nullptr)));
        return false;
    }

    debug("Connected!");

    if ( s = natsConnection_JetStream(&js, conn, &jsOpts); s != NATS_OK ) {
        Error(Fmt("NATS: Failed to initialize JetStream: %s", nats_GetLastError(nullptr)));
        natsConnection_Destroy(conn);
        conn = nullptr;
    }

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
        Error(Fmt("NATS: Failed to add stream (stream_name=%s stream_subject=%s): %s", stream_name.c_str(),
                  stream_subject.c_str(), nats_GetLastError(nullptr)));
        jsCtx_Destroy(js);
        js = nullptr;
        natsConnection_Destroy(conn);
        conn = nullptr;
        return false;
    }

    debug("Stream added!");

    return conn;
}
bool NATSWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;
    jsErrCode jerr;

    if ( ! Connect() ) {
        if ( dropped_writes_log > 0 ) {
            if ( writer_stats.dropped_writes % dropped_writes_log == 0 ) {
                Error(Fmt("Dropped writes [pid=%d dropped_writes=%" PRIu64 "]\n", getpid(),
                          writer_stats.dropped_writes + 1));
            }

            writer_stats.dropped_writes++;
            return true;
        }
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

    if ( s = js_PublishMsgAsync(js, &msg, NULL); s != NATS_OK )
        PublishError(s, nats_GetLastError(nullptr));

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
