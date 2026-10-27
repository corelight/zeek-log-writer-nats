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
#include "config.h"

namespace zeek::plugin::Zeek_Log_Writer_NATS {
Plugin plugin;
}

using namespace zeek::plugin::Zeek_Log_Writer_NATS;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::logging::Component("NATS", detail::NATSWriter::Instantiate));
    AddComponent(new zeek::logging::Component("NATS_CORE", detail::NATSCoreWriter::Instantiate));

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
