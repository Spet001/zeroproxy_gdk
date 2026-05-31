#include "common.hpp"
#include "settings.hpp"
#include "component/scheduler.hpp"
#include "utils/string.hpp"
#include <loader/component_loader.hpp>
#include <map>
#include <fstream>
#include <sstream>

namespace settings {
	namespace {
		config current_config{};
		FILETIME last_write_time{};

		std::map<std::string, WORD> key_map = {
			{"SPACE", VK_SPACE},
			{"TAB", VK_TAB},
			{"ENTER", VK_RETURN},
			{"ESCAPE", VK_ESCAPE},
			{"LSHIFT", VK_LSHIFT},
			{"RSHIFT", VK_RSHIFT},
			{"LCTRL", VK_LCONTROL},
			{"RCTRL", VK_RCONTROL},
			{"LALT", VK_LMENU},
			{"RALT", VK_RMENU},
			{"UP", VK_UP},
			{"DOWN", VK_DOWN},
			{"LEFT", VK_LEFT},
			{"RIGHT", VK_RIGHT},
		};

		WORD parse_key(const std::string& str) {
			auto s = utils::string::to_upper(str);
			if (s.empty()) return 0;
			if (s.length() == 1) {
				return static_cast<WORD>(s[0]);
			}
			if (key_map.contains(s)) {
				return key_map[s];
			}
			return 0;
		}

		std::string key_to_string(WORD key) {
			for (const auto& [name, vk] : key_map) {
				if (vk == key) return name;
			}
			if (key >= 'A' && key <= 'Z') {
				return std::string(1, static_cast<char>(key));
			}
			if (key >= '0' && key <= '9') {
				return std::string(1, static_cast<char>(key));
			}
			return "UNKNOWN";
		}

		std::string get_ini_path() {
			char buffer[MAX_PATH];
			GetCurrentDirectoryA(MAX_PATH, buffer);
			return std::string(buffer) + "\\iw4s.ini";
		}

		void write_default_ini(const std::string& path) {
			std::ofstream out(path);
			if (!out) return;

			out << "[Sensitivity]\n";
			out << "MouseSensitivity=18.0\n";
			out << "StickDeadzone=0.35\n\n";

			out << "[Binds]\n";
			out << "LeftStick_Up=W\n";
			out << "LeftStick_Down=S\n";
			out << "LeftStick_Left=A\n";
			out << "LeftStick_Right=D\n\n";

			out << "Button_A=SPACE\n";
			out << "Button_X=R\n";
			out << "Button_Y=2\n";
			out << "Button_LB=Q\n";
			out << "Button_RB=G\n";
			out << "Button_START=T\n";
			out << "Button_BACK=TAB\n\n";

			out << "Dpad_Up=3\n";
			out << "Dpad_Right=4\n";
			out << "Dpad_Down=5\n";
			out << "Dpad_Left=6\n\n";

			out << "Button_L3=LSHIFT\n";
			out << "Button_R3=V\n";
		}

		void load_ini(const std::string& path) {
			char buffer[256];
			GetPrivateProfileStringA("Sensitivity", "MouseSensitivity", "18.0", buffer, sizeof(buffer), path.c_str());
			current_config.mouse_sensitivity = std::stof(buffer);

			GetPrivateProfileStringA("Sensitivity", "StickDeadzone", "0.35", buffer, sizeof(buffer), path.c_str());
			current_config.stick_key_press_threshold = std::stof(buffer);

			auto get_bind = [&](const char* key, WORD default_vk) -> WORD {
				GetPrivateProfileStringA("Binds", key, key_to_string(default_vk).c_str(), buffer, sizeof(buffer), path.c_str());
				WORD parsed = parse_key(buffer);
				return parsed ? parsed : default_vk;
			};

			current_config.left_stick_keys[0] = get_bind("LeftStick_Up", 'W');
			current_config.left_stick_keys[1] = get_bind("LeftStick_Down", 'S');
			current_config.left_stick_keys[2] = get_bind("LeftStick_Left", 'A');
			current_config.left_stick_keys[3] = get_bind("LeftStick_Right", 'D');

			current_config.face_button_keys[0] = get_bind("Button_A", VK_SPACE);
			current_config.face_button_keys[1] = get_bind("Button_X", 'R');
			current_config.face_button_keys[2] = get_bind("Button_Y", '2');
			current_config.face_button_keys[3] = get_bind("Button_LB", 'Q');
			current_config.face_button_keys[4] = get_bind("Button_RB", 'G');
			current_config.face_button_keys[5] = get_bind("Button_START", 'T');
			current_config.face_button_keys[6] = get_bind("Button_BACK", VK_TAB);

			current_config.dpad_keys[0] = get_bind("Dpad_Up", '3');
			current_config.dpad_keys[1] = get_bind("Dpad_Right", '4');
			current_config.dpad_keys[2] = get_bind("Dpad_Down", '5');
			current_config.dpad_keys[3] = get_bind("Dpad_Left", '6');

			current_config.stick_button_keys[0] = get_bind("Button_L3", VK_LSHIFT);
			current_config.stick_button_keys[1] = get_bind("Button_R3", 'V');
			
			LOG("Component/Settings", INFO, "Loaded iw4s.ini");
		}

		void check_settings() {
			std::string path = get_ini_path();
			WIN32_FILE_ATTRIBUTE_DATA file_data;
			if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &file_data)) {
				if (CompareFileTime(&file_data.ftLastWriteTime, &last_write_time) != 0) {
					last_write_time = file_data.ftLastWriteTime;
					load_ini(path);
				}
			} else {
				write_default_ini(path);
				if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &file_data)) {
					last_write_time = file_data.ftLastWriteTime;
					load_ini(path);
				}
			}
		}
	}

	const config& get() {
		return current_config;
	}

	struct component final : generic_component {
		void post_load() override {
			scheduler::loop(check_settings, scheduler::pipeline::main, 1000ms);
		}
	};
}

REGISTER_COMPONENT(settings::component)
