#include "Plugin.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <zeek/Func.h>
#include <zeek/ID.h>
#include <zeek/Stmt.h>
#include <zeek/Traverse.h>
#include <zeek/util.h>
#include <cstdlib>

#include "NATS.h"
#include "NATSCoreWriter.h"
#include "NATSFastPublishWriter.h"
#include "config.h"

namespace zeek::plugin::Zeek_Log_Writer_NATS {
Plugin plugin;
}

using namespace zeek::plugin::Zeek_Log_Writer_NATS;

namespace {
using namespace zeek::plugin::Zeek_Log_Writer_NATS::detail;

WriterBackend* Instantitate(WriterFrontend* frontend) {
    auto publish_mode = zeek::obj_desc_short(zeek::id::find_val("LogNATS::publish_mode").get());

    debug("publish_mode=%s", publish_mode.c_str());

    if ( publish_mode == "LogNATS::PUBLISH_MODE_CORE" )
        return NATSCoreWriter::Instantiate(frontend);
    else if ( publish_mode == "LogNATS::PUBLISH_MODE_ASYNC" )
        return NATSWriter::Instantiate(frontend);
    else if ( publish_mode == "LogNATS::PUBLISH_MODE_FAST" )
        return NATSFastPublishWriter::Instantiate(frontend);

    eprintf("Unknown publish_mode=%s", publish_mode.c_str());
    return nullptr;
}
} // namespace

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::logging::Component("NATS", Instantitate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Log_Writer_NATS";
    config.description = "Log writers sending to NATS";
    config.version.major = VERSION_MAJOR;
    config.version.minor = VERSION_MINOR;
    config.version.patch = VERSION_PATCH;
    return config;
}

void Plugin::InitPostScript() {}

void Plugin::Done() {}
