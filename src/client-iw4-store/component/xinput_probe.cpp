#include "common.hpp"

#include "component/scheduler.hpp"

#include <loader/component_loader.hpp>

#include <xinput.h>

namespace xinput_probe {
	namespace {
		using xinput_get_state_t = DWORD(WINAPI*)(DWORD, XINPUT_STATE*);

		constexpr float mouse_sensitivity = 18.0f;
		constexpr float stick_key_press_threshold = 0.35f;

		constexpr std::array<const char*, 3> xinput_dll_names{
			"xinput1_4.dll",
			"xinput1_3.dll",
			"xinput9_1_0.dll",
		};

		constexpr std::array<std::pair<WORD, const char*>, 14> button_names{
			std::pair{XINPUT_GAMEPAD_DPAD_UP, "DPAD_UP"},
			std::pair{XINPUT_GAMEPAD_DPAD_DOWN, "DPAD_DOWN"},
			std::pair{XINPUT_GAMEPAD_DPAD_LEFT, "DPAD_LEFT"},
			std::pair{XINPUT_GAMEPAD_DPAD_RIGHT, "DPAD_RIGHT"},
			std::pair{XINPUT_GAMEPAD_START, "START"},
			std::pair{XINPUT_GAMEPAD_BACK, "BACK"},
			std::pair{XINPUT_GAMEPAD_LEFT_THUMB, "L3"},
			std::pair{XINPUT_GAMEPAD_RIGHT_THUMB, "R3"},
			std::pair{XINPUT_GAMEPAD_LEFT_SHOULDER, "LB"},
			std::pair{XINPUT_GAMEPAD_RIGHT_SHOULDER, "RB"},
			std::pair{XINPUT_GAMEPAD_A, "A"},
			std::pair{XINPUT_GAMEPAD_B, "B"},
			std::pair{XINPUT_GAMEPAD_X, "X"},
			std::pair{XINPUT_GAMEPAD_Y, "Y"},
		};

		constexpr std::array<WORD, 4> left_stick_keys{
			'W',
			'S',
			'A',
			'D',
		};

		constexpr std::array<WORD, 8> face_button_keys{
			VK_SPACE, // A -> Jump
			'C',      // B -> Crouch / prone hold
			'R',      // X -> Reload
			'2',      // Y -> Weapon swap
			'Q',      // LB -> Tactical
			'G',      // RB -> Grenade
			'T',      // START -> Push-to-talk
			VK_TAB,   // BACK -> Scoreboard
		};

		constexpr std::array<WORD, 4> dpad_keys{
			'3',      // Up -> Killstreak 1
			'4',      // Right -> Killstreak 2
			'5',      // Down -> Killstreak 3
			'6',      // Left -> Killstreak 4
		};

		constexpr std::array<WORD, 2> stick_button_keys{
			VK_LSHIFT, // L3 -> Sprint
			'V',       // R3 -> Melee
		};

		struct injected_state {
			std::array<bool, left_stick_keys.size()> left_stick_keys_down{};
			std::array<bool, face_button_keys.size()> face_button_keys_down{};
			std::array<bool, dpad_keys.size()> dpad_keys_down{};
			std::array<bool, stick_button_keys.size()> stick_button_keys_down{};
			bool left_mouse_down{};
			bool right_mouse_down{};
			float mouse_x_remainder{};
			float mouse_y_remainder{};
		};

		struct pad_snapshot {
			bool connected{};
			DWORD packet_number{};
			WORD buttons{};
			SHORT thumb_lx{};
			SHORT thumb_ly{};
			SHORT thumb_rx{};
			SHORT thumb_ry{};
			BYTE left_trigger{};
			BYTE right_trigger{};
		};

		struct state_cache {
			HMODULE module{};
			xinput_get_state_t get_state{};
			std::array<pad_snapshot, XUSER_MAX_COUNT> pads{};
			bool initialized{};
			DWORD active_index{XUSER_MAX_COUNT};
			injected_state injected{};
		};

		state_cache cache{};

		bool is_game_window_active() {
			const auto foreground = GetForegroundWindow();
			if (foreground == nullptr) {
				return false;
			}

			DWORD foreground_process_id{};
			GetWindowThreadProcessId(foreground, &foreground_process_id);
			return foreground_process_id == GetCurrentProcessId();
		}

		bool any_pressed(const std::array<bool, left_stick_keys.size()>& keys) {
			for (const auto key_down : keys) {
				if (key_down) {
					return true;
				}
			}

			return false;
		}

		template <std::size_t N>
		bool any_pressed(const std::array<bool, N>& keys) {
			for (const auto key_down : keys) {
				if (key_down) {
					return true;
				}
			}

			return false;
		}

		void send_key_event(const WORD key, const bool down) {
			INPUT input{};
			input.type = INPUT_KEYBOARD;
			input.ki.wScan = static_cast<WORD>(MapVirtualKeyA(key, MAPVK_VK_TO_VSC));
			input.ki.dwFlags = KEYEVENTF_SCANCODE | (down ? 0 : KEYEVENTF_KEYUP);
			SendInput(1, &input, sizeof(input));
		}

		void send_mouse_button_event(const DWORD down_flag, const DWORD up_flag, const bool down) {
			INPUT input{};
			input.type = INPUT_MOUSE;
			input.mi.dwFlags = down ? down_flag : up_flag;
			SendInput(1, &input, sizeof(input));
		}

		void send_mouse_move(float& x_remainder, float& y_remainder, const float x_delta, const float y_delta) {
			x_remainder += x_delta;
			y_remainder += y_delta;

			const auto dx = static_cast<LONG>(std::lround(x_remainder));
			const auto dy = static_cast<LONG>(std::lround(y_remainder));
			if (dx == 0 && dy == 0) {
				return;
			}

			x_remainder -= static_cast<float>(dx);
			y_remainder -= static_cast<float>(dy);

			INPUT input{};
			input.type = INPUT_MOUSE;
			input.mi.dwFlags = MOUSEEVENTF_MOVE;
			input.mi.dx = dx;
			input.mi.dy = dy;
			SendInput(1, &input, sizeof(input));
		}

		float normalize_thumb_axis(const SHORT value, const SHORT deadzone) {
			const auto abs_value = std::abs(static_cast<int>(value));
			if (abs_value <= deadzone) {
				return 0.0f;
			}

			const auto max_value = static_cast<float>(std::numeric_limits<SHORT>::max() - deadzone);
			const auto normalized = (static_cast<float>(abs_value - deadzone) / max_value);
			return std::clamp(normalized, 0.0f, 1.0f) * (value < 0 ? -1.0f : 1.0f);
		}

		void set_key_state(std::array<bool, left_stick_keys.size()>& state, const std::size_t index, const bool down) {
			if (state[index] == down) {
				return;
			}

			state[index] = down;
			send_key_event(left_stick_keys[index], down);
		}

		void set_button_state(std::array<bool, face_button_keys.size()>& state, const std::size_t index, const bool down) {
			if (state[index] == down) {
				return;
			}

			state[index] = down;
			send_key_event(face_button_keys[index], down);
		}

		void set_button_state(std::array<bool, dpad_keys.size()>& state, const std::size_t index, const bool down) {
			if (state[index] == down) {
				return;
			}

			state[index] = down;
			send_key_event(dpad_keys[index], down);
		}

		void set_button_state(std::array<bool, stick_button_keys.size()>& state, const std::size_t index, const bool down) {
			if (state[index] == down) {
				return;
			}

			state[index] = down;
			send_key_event(stick_button_keys[index], down);
		}

		void release_all_inputs(injected_state& injected) {
			for (std::size_t i = 0; i < injected.left_stick_keys_down.size(); ++i) {
				set_key_state(injected.left_stick_keys_down, i, false);
			}

			for (std::size_t i = 0; i < injected.face_button_keys_down.size(); ++i) {
				set_button_state(injected.face_button_keys_down, i, false);
			}

			for (std::size_t i = 0; i < injected.dpad_keys_down.size(); ++i) {
				set_button_state(injected.dpad_keys_down, i, false);
			}

			for (std::size_t i = 0; i < injected.stick_button_keys_down.size(); ++i) {
				set_button_state(injected.stick_button_keys_down, i, false);
			}

			if (injected.left_mouse_down) {
				injected.left_mouse_down = false;
				send_mouse_button_event(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, false);
			}

			if (injected.right_mouse_down) {
				injected.right_mouse_down = false;
				send_mouse_button_event(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, false);
			}

			injected.mouse_x_remainder = 0.0f;
			injected.mouse_y_remainder = 0.0f;
		}

		bool load_xinput() {
			if (cache.get_state != nullptr) {
				return true;
			}

			for (const auto* dll_name : xinput_dll_names) {
				cache.module = LoadLibraryA(dll_name);
				if (cache.module == nullptr) {
					continue;
				}

				cache.get_state = reinterpret_cast<xinput_get_state_t>(GetProcAddress(cache.module, "XInputGetState"));
				if (cache.get_state != nullptr) {
					LOG("Component/XInputProbe", INFO, "Loaded {}", dll_name);
					return true;
				}

				FreeLibrary(cache.module);
				cache.module = nullptr;
			}

			if (!cache.initialized) {
				LOG("Component/XInputProbe", WARN, "XInput runtime not found, controller support disabled");
				cache.initialized = true;
			}

			return false;
		}

		std::string describe_buttons(const WORD buttons) {
			std::string result;

			for (const auto& [mask, name] : button_names) {
				if ((buttons & mask) == 0) {
					continue;
				}

				if (!result.empty()) {
					result.append(",");
				}

				result.append(name);
			}

			if (result.empty()) {
				result = "none";
			}

			return result;
		}

		void log_pad_state(const DWORD index, const XINPUT_STATE& state) {
			const auto& gp = state.Gamepad;
			LOG("Component/XInputProbe", INFO,
				"pad {} packet={} buttons={} (0x{:04X}) lx={} ly={} rx={} ry={} lt={} rt={}",
				index,
				state.dwPacketNumber,
				describe_buttons(gp.wButtons),
				gp.wButtons,
				gp.sThumbLX,
				gp.sThumbLY,
				gp.sThumbRX,
				gp.sThumbRY,
				gp.bLeftTrigger,
				gp.bRightTrigger);
		}

		void apply_active_controller(const DWORD index, const XINPUT_STATE& state) {
			auto& injected = cache.injected;
			const auto& gp = state.Gamepad;

			const auto left_x = normalize_thumb_axis(gp.sThumbLX, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
			const auto left_y = normalize_thumb_axis(gp.sThumbLY, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
			const auto right_x = normalize_thumb_axis(gp.sThumbRX, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);
			const auto right_y = normalize_thumb_axis(gp.sThumbRY, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);

			set_key_state(injected.left_stick_keys_down, 0, left_y > stick_key_press_threshold);
			set_key_state(injected.left_stick_keys_down, 1, left_y < -stick_key_press_threshold);
			set_key_state(injected.left_stick_keys_down, 2, left_x < -stick_key_press_threshold);
			set_key_state(injected.left_stick_keys_down, 3, left_x > stick_key_press_threshold);

			set_button_state(injected.face_button_keys_down, 0, (gp.wButtons & XINPUT_GAMEPAD_A) != 0);
			set_button_state(injected.face_button_keys_down, 1, (gp.wButtons & XINPUT_GAMEPAD_B) != 0);
			set_button_state(injected.face_button_keys_down, 2, (gp.wButtons & XINPUT_GAMEPAD_X) != 0);
			set_button_state(injected.face_button_keys_down, 3, (gp.wButtons & XINPUT_GAMEPAD_Y) != 0);
			set_button_state(injected.face_button_keys_down, 4, (gp.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0);
			set_button_state(injected.face_button_keys_down, 5, (gp.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0);
			set_button_state(injected.face_button_keys_down, 6, (gp.wButtons & XINPUT_GAMEPAD_START) != 0);
			set_button_state(injected.face_button_keys_down, 7, (gp.wButtons & XINPUT_GAMEPAD_BACK) != 0);

			set_button_state(injected.stick_button_keys_down, 0, (gp.wButtons & XINPUT_GAMEPAD_LEFT_THUMB) != 0);
			set_button_state(injected.stick_button_keys_down, 1, (gp.wButtons & XINPUT_GAMEPAD_RIGHT_THUMB) != 0);

			set_button_state(injected.dpad_keys_down, 0, (gp.wButtons & XINPUT_GAMEPAD_DPAD_UP) != 0);
			set_button_state(injected.dpad_keys_down, 1, (gp.wButtons & XINPUT_GAMEPAD_DPAD_RIGHT) != 0);
			set_button_state(injected.dpad_keys_down, 2, (gp.wButtons & XINPUT_GAMEPAD_DPAD_DOWN) != 0);
			set_button_state(injected.dpad_keys_down, 3, (gp.wButtons & XINPUT_GAMEPAD_DPAD_LEFT) != 0);

			// Map triggers: RT -> Left mouse (fire), LT -> Right mouse (aim)
			const bool right_trigger_down = gp.bRightTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD;
			const bool left_trigger_down = gp.bLeftTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD;
			if (injected.left_mouse_down != right_trigger_down) {
				injected.left_mouse_down = right_trigger_down;
				send_mouse_button_event(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, right_trigger_down);
			}

			if (injected.right_mouse_down != left_trigger_down) {
				injected.right_mouse_down = left_trigger_down;
				send_mouse_button_event(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, left_trigger_down);
			}

			const auto mouse_scale = mouse_sensitivity * 10.0f;
			send_mouse_move(injected.mouse_x_remainder, injected.mouse_y_remainder, right_x * mouse_scale, -right_y * mouse_scale);

			if (cache.active_index != index) {
				LOG("Component/XInputProbe", INFO, "active pad {}", index);
				cache.active_index = index;
			}
		}

		void poll_controllers() {
			if (!load_xinput()) {
				return;
			}

			if (!is_game_window_active()) {
				if (cache.active_index != XUSER_MAX_COUNT || any_pressed(cache.injected.left_stick_keys_down) || any_pressed(cache.injected.face_button_keys_down) ||
					any_pressed(cache.injected.dpad_keys_down) || any_pressed(cache.injected.stick_button_keys_down) ||
					cache.injected.left_mouse_down || cache.injected.right_mouse_down) {
					release_all_inputs(cache.injected);
					cache.active_index = XUSER_MAX_COUNT;
				}

				return;
			}

			DWORD active_index = XUSER_MAX_COUNT;
			XINPUT_STATE active_state{};

			for (DWORD index = 0; index < XUSER_MAX_COUNT; ++index) {
				XINPUT_STATE state{};
				const auto result = cache.get_state(index, &state);
				auto& snapshot = cache.pads[index];

				if (result != ERROR_SUCCESS) {
					if (snapshot.connected) {
						snapshot.connected = false;
						LOG("Component/XInputProbe", INFO, "pad {} disconnected", index);
					}

					continue;
				}

				const auto& gp = state.Gamepad;
				const bool first_connect = !snapshot.connected;
				const bool changed = first_connect || snapshot.packet_number != state.dwPacketNumber || snapshot.buttons != gp.wButtons ||
					snapshot.thumb_lx != gp.sThumbLX || snapshot.thumb_ly != gp.sThumbLY || snapshot.thumb_rx != gp.sThumbRX ||
					snapshot.thumb_ry != gp.sThumbRY || snapshot.left_trigger != gp.bLeftTrigger || snapshot.right_trigger != gp.bRightTrigger;

				if (first_connect) {
					snapshot.connected = true;
					LOG("Component/XInputProbe", INFO, "pad {} connected", index);
				}

				if (active_index == XUSER_MAX_COUNT) {
					active_index = index;
					active_state = state;
				}

				if (changed) {
					log_pad_state(index, state);
					snapshot.packet_number = state.dwPacketNumber;
					snapshot.buttons = gp.wButtons;
					snapshot.thumb_lx = gp.sThumbLX;
					snapshot.thumb_ly = gp.sThumbLY;
					snapshot.thumb_rx = gp.sThumbRX;
					snapshot.thumb_ry = gp.sThumbRY;
					snapshot.left_trigger = gp.bLeftTrigger;
					snapshot.right_trigger = gp.bRightTrigger;
				}
			}

			if (active_index == XUSER_MAX_COUNT) {
				if (cache.active_index != XUSER_MAX_COUNT || any_pressed(cache.injected.left_stick_keys_down) || any_pressed(cache.injected.face_button_keys_down) ||
					any_pressed(cache.injected.dpad_keys_down) || any_pressed(cache.injected.stick_button_keys_down) ||
					cache.injected.left_mouse_down || cache.injected.right_mouse_down) {
					release_all_inputs(cache.injected);
					cache.active_index = XUSER_MAX_COUNT;
				}

				return;
			}

			if (cache.active_index != active_index) {
				release_all_inputs(cache.injected);
			}

			apply_active_controller(active_index, active_state);
		}
	}

	struct component final : generic_component {
		void post_load() override {
			scheduler::loop(poll_controllers, scheduler::pipeline::main, 16ms);
		}
	};
}

REGISTER_COMPONENT(xinput_probe::component)