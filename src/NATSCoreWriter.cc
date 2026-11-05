#include "NATSCoreWriter.h"

#include <nats/nats.h>


using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

NATSCoreWriter::NATSCoreWriter(WriterFrontend* frontend) : NATSWriter(frontend) {}

bool NATSCoreWriter::DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) {
    natsMsg* msg;

    if ( ! FormatMessage(&msg, num_fields, fields, vals) ) {
        DropWrite(NATS_ERR, "FormatMessage() failed");
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
