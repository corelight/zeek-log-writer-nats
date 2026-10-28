#include "NATSFastPublishWriter.h"

#include <nats/nats.h>
#include <nats/status.h>

#include "Connection.h"
#include "NATS.h"
#include "Plugin.h"

using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSFastPublishWriter::NATSFastPublishWriter(WriterFrontend* frontend)
    : NATSWriter(frontend, /*send_heartbeats=*/true) {
    constexpr uint64_t uint16max = std::numeric_limits<uint16_t>::max();

    auto tmp_flow = zeek::id::find_val<zeek::StringVal>("LogNATS::fast_publish_flow")->AsCount();

    if ( tmp_flow > uint16max ) {
        eprintf("flow value too large %" PRIu64, tmp_flow);
        tmp_flow = uint16max;
    }

    opts.flow = tmp_flow;

    auto tmp_max_outstanding_acks =
        zeek::id::find_val<zeek::StringVal>("LogNATS::fast_publish_max_outstanding_acks")->AsCount();

    if ( tmp_max_outstanding_acks > uint16max ) {
        eprintf("max_outstanding_acks too large: %" PRIu64, tmp_max_outstanding_acks);
        tmp_max_outstanding_acks = uint16max;
    }

    opts.max_outstanding_acks = tmp_max_outstanding_acks;

    opts.max_batch_size = zeek::id::find_val<zeek::StringVal>("LogNATS::fast_publish_max_batch_size")->AsCount();
    opts.commit_timeout_ms =
        static_cast<int64_t>(zeek::id::find_val("LogNATS::fast_publish_commit_timeout")->AsInterval() * 1000);

    auto batch_policy_str = zeek::obj_desc_short(zeek::id::find_val("LogNATS::fast_publish_batch_policy").get());

    if ( batch_policy_str == "LogNATS::BATCH_EXCLUSIVE" )
        batch_policy = FastPublishBatchPolicy::EXCLUSIVE;
    else if ( batch_policy_str == "LogNATS::BATCH_SHARED" )
        batch_policy = FastPublishBatchPolicy::SHARED;
    else {
        eprintf("Invalid fast_publish_batch_policy: %s", batch_policy_str.c_str());
        abort(); // This really should not happen...
    }

    debug("fast_publish: path=%s batch_policy=%s flow=%" PRIu16 " max_batch_size=%zu max_outstanding_acks=%" PRIu16
          " commit_timeout_ms=%" PRId64,
          Info().path, batch_policy_str.c_str(), opts.flow, opts.max_batch_size, opts.max_outstanding_acks,
          opts.commit_timeout_ms);
}


bool NATSFastPublishWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;

    if ( Conn()->Epoch() == 0 ) {
        // XXX: Can we do better than dropping everything
        // before being connected for the first time?
        DropWrite(NATS_NOT_YET_CONNECTED, "not yet connected");
        return true;
    }

    if ( ! fast_publisher )
        fast_publisher = Conn()->CreateFastPublisher(batch_policy, opts);


    natsMsg* msg;
    if ( ! FormatMessage(&msg, num_fields, fields, vals) ) {
        DropWrite(NATS_ERR, "FormatMessage() failed");
        return true;
    }

    if ( auto [ok, status, error] = fast_publisher->AddMsg(msg); ! ok )
        DropWrite(status, error->c_str());

    natsMsg_Destroy(msg);
    return true;
}


bool NATSFastPublishWriter::DoHeartbeat(double network_time, double current_time) {
    debug("DoHeartbeat");

    if ( fast_publisher )
        fast_publisher->Commit();

    return true;
}


bool NATSFastPublishWriter::DoFinish(double network_time) {
    debug("DoFinish");

    if ( fast_publisher )
        fast_publisher->Commit();

    return true;
}
