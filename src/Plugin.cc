// Inspiration from the Python version, but totally hacked together.
//
// https://github.com/python/cpython/pull/96123/files
#include "Plugin.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <zeek/Func.h>
#include <zeek/ID.h>
#include <zeek/Stmt.h>
#include <zeek/Traverse.h>
#include <zeek/telemetry/Manager.h>
#include <zeek/util.h>
#include <cstdlib>
#include <memory>

#include "NATS.h"
#include "SharedClient.h"
#include "config.h"

namespace zeek::plugin::Zeek_Log_Writer_NATS {
Plugin plugin;
}

using namespace zeek::plugin::Zeek_Log_Writer_NATS;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::logging::Component("NATS", detail::NATSWriter::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Log_Writer_NATS";
    config.description = "Log writer sending to NATS";
    config.version.major = VERSION_MAJOR;
    config.version.minor = VERSION_MINOR;
    config.version.patch = VERSION_PATCH;
    return config;
}

void Plugin::InitPostScript() {
    connections_gauge =
        zeek::telemetry_mgr->GaugeInstance("zeek", "nats-log-writer-connections", {},
                                           "Established NATS connections shared by the NATS log writers", "",
                                           []() { return static_cast<double>(detail::SharedClient::Connections()); });
}

void Plugin::Done() {
    // All writers and their connections are gone at this point. Release
    // the NATS library's remaining global resources.
    nats_Close();
}
