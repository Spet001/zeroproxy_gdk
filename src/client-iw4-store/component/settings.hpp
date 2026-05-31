#pragma once
#include "common.hpp"
#include <array>

namespace settings {
	struct config {
		float mouse_sensitivity{18.0f};
		float stick_key_press_threshold{0.35f};

		std::array<WORD, 4> left_stick_keys{'W', 'S', 'A', 'D'};
		std::array<WORD, 7> face_button_keys{VK_SPACE, 'R', '2', 'Q', 'G', 'T', VK_TAB};
		std::array<WORD, 4> dpad_keys{'3', '4', '5', '6'};
		std::array<WORD, 2> stick_button_keys{VK_LSHIFT, 'V'};
	};

	const config& get();
}
