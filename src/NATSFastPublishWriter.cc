#include "NATSFastPublishWriter.h"

#include <fast_publish.h>
#include <nats/nats.h>
#include <nats/status.h>

#include "NATS.h"
#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSFastPublishWriter::NATSFastPublishWriter(WriterFrontend* frontend)
    : NATSWriter(frontend, /*send_heartbeats=*/true) {}

namespace {
void fp_err_handler(natsStatus status, const char* description, void* closure) {
    auto* writer = static_cast<NATSFastPublishWriter*>(closure);
    writer->ErrorHandler(status, description);
}
} // namespace


bool NATSFastPublishWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;

    if ( Conn()->Epoch() == 0 ) {
        // XXX: Can we do better than that?
        DropWrite(NATS_NOT_YET_CONNECTED, "not yet connected");
        return true;
    }


    if ( ! fp_ctx ) {
        jsFastPublisherOptions fp_opts;
        if ( s = jsFastPublisherOptions_Init(&fp_opts); s != NATS_OK ) {
            eprintf("failed to create options");
            return true;
        }

        fp_opts.ErrHandler = fp_err_handler;
        fp_opts.ErrHandlerClosure = this;
        fp_opts.ContinueOnGap = continue_on_gap;

        natsConnection* nc = Conn()->RawConnection();

        // Create a batch here if needed. It'll be committed
        // when it is full, or in DoHeartbeat() or DoFinish().
        //
        // This call is blocking!!!
        if ( s = jsFastPublishCtx_Create(&fp_ctx, nc, &fp_opts); s != NATS_OK ) {
            eprintf("jsPublishCtx_Create failed");
            return true;
        }
    }


    // TODO: Factor out!
    auto& desc = Desc();
    desc.Clear();

    if ( ! Formatter().Describe(&desc, num_fields, fields, vals) ) {
        DropWrite(NATS_ERR, "formatter describe failed");
        return true;
    }

    const char* data = (const char*)desc.Bytes();
    int data_len = desc.Size();

    natsMsg* msg;
    if ( s = natsMsg_Create(&msg, PublishSubject().c_str(), nullptr /*reply*/, data, data_len); s != NATS_OK ) {
        PublishError(s, 0, "failed to create message");
        return true;
    }

    // How much more room in the batch before we commit?
    const size_t left = max_batch_size - batch_size;

    // Do we need BatchMsgOpts
    // jsBatchMsgOpts opts;
    // jsBatchMsgOpts_Init()

    if ( left > 1 ) {
        if ( s = jsFastPublish_AddMsg(/*ack=*/nullptr, fp_ctx, msg, /*opts=*/nullptr); s != NATS_OK ) {
            PublishError(s, 0, "jsFastPublish_AddMsg() failed");
            natsMsg_Destroy(msg);
            return false;
        }

        ++batch_size;
    }
    else if ( left == 1 ) {
        jsPubAck* pub_ack = nullptr;

        if ( s = jsFastPublish_CommitMsg(&pub_ack, fp_ctx, msg, /*opts=*/nullptr, commit_timeout_ms); s != NATS_OK ) {
            PublishError(s, 0, "jsFastPublish_CommitMsg() failed");
        }
        else {
            debug("Commit Sequence=%" PRIu64 " Count=%" PRIu64, pub_ack->Sequence, pub_ack->Count);

            jsPubAck_Destroy(pub_ack); // should we do something with it? metrics?
            pub_ack = nullptr;
        }

        jsFastPublish_Destroy(fp_ctx);
        fp_ctx = nullptr;
        batch_size = 0;
    }
    else {
        eprintf("unexpected left %zu", left);
        abort();
    }

    natsMsg_Destroy(msg);
    return true;
}


void NATSFastPublishWriter::ErrorHandler(natsStatus status, const char* description) {
    const char* status_str = natsStatus_GetText(status);
    eprintf("ERROR %s: %s", status_str, description);

    // Not really sure what to do here? Just log an error, increment
    // some error and move on?
}


bool NATSFastPublishWriter::DoHeartbeat(double network_time, double current_time) {
    debug("DoHeartbeat");
    CommitBatch();
    return true;
}


bool NATSFastPublishWriter::DoFinish(double network_time) {
    debug("DoFinish");
    CommitBatch();
    return true;
}


bool NATSFastPublishWriter::CommitBatch() {
    debug("CommitBatch");

    if ( ! fp_ctx )
        return true;

    natsStatus s = NATS_OK;
    jsPubAck* pub_ack = nullptr;

    if ( s = jsFastPublish_Close(&pub_ack, fp_ctx, commit_timeout_ms); s != NATS_OK ) {
        const char* status_str = natsStatus_GetText(s);

        // TODO: Metric
        eprintf("jsFastPublish_Close() failed: %s", status_str);
    }

    debug("commit Sequence=%" PRIu64 " Count=%" PRIu64, pub_ack->Sequence, pub_ack->Count);

    jsPubAck_Destroy(pub_ack); // should we do something with it? metrics?
    pub_ack = nullptr;
    jsFastPublish_Destroy(fp_ctx);

    fp_ctx = nullptr;
    batch_size = 0;

    return true;
}
