#pragma once
#include <zeek/plugin/Plugin.h>

namespace zeek::plugin {
namespace Zeek_Log_Writer_NATS {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
    void Done() override;

    void InstallTrampolines();

private:
    void* unused = nullptr;
};

extern Plugin plugin;

#define debug(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Log_Writer_NATS::plugin, __VA_ARGS__)

} // namespace Zeek_Log_Writer_NATS
} // namespace zeek::plugin
