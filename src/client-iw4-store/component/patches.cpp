#include "common.hpp"

#include "component/scheduler.hpp"
#include "game/game.hpp"

#include <component/localized_strings.hpp>
#include <loader/component_loader.hpp>
#include <utils/hook.hpp>
#include <utils/string.hpp>

#include <version.hpp>

struct IDirect3D9;
namespace proxy {
	void on_direct3d9_created(IDirect3D9* direct3d9) {}
}

namespace patches {
	namespace {
		utils::hook::detour bd_log_message_hook;

		utils::hook::iat_detour create_window_ex_a_hook;
		utils::hook::iat_detour create_window_ex_w_hook;
		WNDPROC iw4_window_proc_original{};

		LRESULT CALLBACK iw4_window_proc_stub(HWND hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
			return CallWindowProcA(iw4_window_proc_original, hwnd, msg, w_param, l_param);
		}

		HWND create_window_ex_a_stub(DWORD dw_ex_style, LPCSTR lp_class_name, LPCSTR lp_window_name, DWORD dw_style, int x, int y, int n_width, int n_height,
			HWND hwnd_parent, HMENU h_menu, HINSTANCE h_instance, LPVOID lp_param)
		{
			LPCSTR lp_window_name_patched = lp_window_name;
			if (lp_class_name && reinterpret_cast<ULONG_PTR>(lp_class_name) > 0xFFFF) {
				LOG("Component/Patches", INFO, "CreateWindowExA: class='{}', name='{}'", lp_class_name, lp_window_name ? lp_window_name : "");
				if (strcmp(lp_class_name, "IW4") == 0) {
					lp_window_name_patched = "IW4S-ResurgeGDK by Lifix Luxploit and Spet | " GIT_DESCRIBE;
				}
			}

			auto* const hwnd = create_window_ex_a_hook.invoke<HWND>(dw_ex_style, lp_class_name, lp_window_name_patched, dw_style, x, y, n_width, n_height, hwnd_parent,
				h_menu, h_instance, lp_param);

			if (hwnd != nullptr && !iw4_window_proc_original) {
				LOG("Component/Patches", INFO, "Hooking WndProc for HWND {}", (void*)hwnd);
				iw4_window_proc_original = reinterpret_cast<WNDPROC>(SetWindowLongPtrA(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(iw4_window_proc_stub)));
			}

			return hwnd;
		}

		HWND create_window_ex_w_stub(DWORD dw_ex_style, LPCWSTR lp_class_name, LPCWSTR lp_window_name, DWORD dw_style, int x, int y, int n_width, int n_height,
			HWND hwnd_parent, HMENU h_menu, HINSTANCE h_instance, LPVOID lp_param)
		{
			auto* const hwnd = create_window_ex_w_hook.invoke<HWND>(dw_ex_style, lp_class_name, lp_window_name, dw_style, x, y, n_width, n_height, hwnd_parent,
				h_menu, h_instance, lp_param);

			if (hwnd != nullptr && !iw4_window_proc_original) {
				LOG("Component/Patches", INFO, "Hooking WndProc for HWND {}", (void*)hwnd);
				iw4_window_proc_original = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(iw4_window_proc_stub)));
			}

			return hwnd;
		}

		void bd_log_message_stub(int type, const char* category, const char* source, const char* source_file, const char* source_function, int a6,
			const char* message, ...)
		{
			va_list args;
			va_start(args, message);

			char buffer[1024];
			vsnprintf(buffer, sizeof(buffer), message, args);

			va_end(args);

			LOG("Component/Patches", DEBUG, "[DW] [{}{}] [{}/{}]: {}", category, type, source, source_function, buffer);
			return bd_log_message_hook.invoke<void>(type, category, source, source_file, source_function, a6, "%s", buffer);
		}
	}

	struct component final : generic_component {
		void post_load() override {
			bd_log_message_hook.create(game::bdLogMessage, bd_log_message_stub);
			create_window_ex_a_hook.create(utils::nt::library(), "user32.dll", "CreateWindowExA", create_window_ex_a_stub);
			create_window_ex_w_hook.create(utils::nt::library(), "user32.dll", "CreateWindowExW", create_window_ex_w_stub);
		}
	};
}

REGISTER_COMPONENT(patches::component)