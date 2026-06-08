#include "common.hpp"
#include <loader/component_loader.hpp>
#include <component/scheduler.hpp>

#if defined(_WIN64)
#include "uwp_hook.hpp"

namespace uwp {
    class component final : public generic_component {
    public:
        static void hook_query_api() {
            static bool hooked = false;
            if (hooked) return;
            utils::nt::library lib("xgameruntime.dll");
            if (!lib.is_valid()) return;

            // Initialize DLC Unlocker UWP Hooks once xgameruntime is loaded
            init_standalone_hooks();
            hooked = true;
        }

        void post_load() override {
            scheduler::loop(hook_query_api, scheduler::pipeline::async);
        }
    };
}

REGISTER_COMPONENT(uwp::component)
#endif


