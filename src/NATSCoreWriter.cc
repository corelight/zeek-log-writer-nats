#include "NATSCoreWriter.h"

#include <nats/nats.h>


using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSCoreWriter::NATSCoreWriter(WriterFrontend* frontend) : NATSWriter(frontend, /*send_heartbeats=*/false) {}

bool NATSCoreWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsStatus s = NATS_OK;

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

    auto [ok, status, error] = Conn()->Publish(msg);

    if ( ! ok ) // We fall through to true
        PublishError(status, 0, error->c_str());

    natsMsg_Destroy(msg);

    return true;
}


bool NATSCoreWriter::DoFinish(double network_time) {
    // should natsConnection_Flush here...
    return true;
}
