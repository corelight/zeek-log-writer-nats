#pragma once
#include <zeek/plugin/Plugin.h>

namespace zeek::plugin {
namespace Zeek_Log_Writer_NATS {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
    void Done() override;
};

extern Plugin plugin;

#define debug(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Log_Writer_NATS::plugin, __VA_ARGS__)

// Poor man's print to stderr prefixed with NATS: and flush via \n
#define eprintf(...)                                                                                                   \
    do {                                                                                                               \
        fprintf(stderr, "NATS: ");                                                                                     \
        fprintf(stderr, __VA_ARGS__);                                                                                  \
        fprintf(stderr, "\n");                                                                                         \
    } while ( 0 );

} // namespace Zeek_Log_Writer_NATS
} // namespace zeek::plugin
