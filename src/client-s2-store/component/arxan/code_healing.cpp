#include "common.hpp"
#include <loader/component_loader.hpp>

#include "integrity_locations.hpp"
#include "breakpoint_locations.hpp"
#include "code_healing_locations.hpp"

#include "game/game.hpp"

#include <utils/hook.hpp>
#include <utils/string.hpp>

#include <udis86.h>

#include <span>

namespace arxan::code_healing
{
	struct dynamic_patch_region
	{
		uint64_t start;
		uint64_t end;
	};

	inline std::vector<dynamic_patch_region> active_patches;
	inline std::mutex active_patches_mutex;

	void register_patch(uint64_t address, size_t size)
	{
		std::lock_guard<std::mutex> lock(active_patches_mutex);
		active_patches.push_back({ address, address + size });
#ifdef ARXAN_DEBUG
		OutputDebugStringA(utils::string::va("[Code Healing] Registered patch region: %llX - %llX\n", address, address + size));
#else
		LOG("Arxan/CodeHealing", INFO, "Registered patch region: {:X} - {:X}", address, address + size);
#endif
	}

	namespace
	{
		using patch_list = std::span<const uint64_t>;

		struct arxan_patch_lists
		{
			patch_list intact_integrity;
			patch_list big_intact_integrity;
			patch_list split_integrity;
			patch_list big_split_integrity;
			patch_list al_healing;
			patch_list eax_healing;
			patch_list eax_split_healing;
			patch_list int2d_breakpoint;
		};

		constexpr std::array<uint64_t, 0> empty_offsets{};

		constexpr arxan_patch_lists mp_patches
		{
			mp::intact_integrity_offsets,
			mp::big_intact_integrity_offsets,
			mp::split_integrity_offsets,
			mp::big_split_integrity_offsets,
			mp::al_healing_offsets,
			mp::eax_healing_offsets,
			mp::eax_split_healing_offsets,
			mp::int2d_breakpoint_offsets,
		};

		constexpr arxan_patch_lists sp_patches
		{
			sp::intact_integrity_offsets,
			sp::big_intact_integrity_offsets,
			empty_offsets,
			sp::big_split_integrity_offsets,
			sp::al_healing_offsets,
			sp::eax_healing_offsets,
			sp::eax_split_healing_offsets,
			sp::int2d_breakpoint_offsets,
		};

		const arxan_patch_lists& current_patches()
		{
			return game::environment::is_mp()
				? mp_patches
				: sp_patches;
		}

		struct patch_region
		{
			patch_list offsets;
			uint64_t size;
		};

		const std::array<patch_region, 8>& current_regions()
		{
			static const std::array<patch_region, 8> mp_regions
			{
				patch_region{mp::big_intact_integrity_offsets, 0xA},
				patch_region{mp::big_split_integrity_offsets, 0x5},
				patch_region{mp::intact_integrity_offsets, 0x7},
				patch_region{mp::split_integrity_offsets, 0x5},
				patch_region{mp::al_healing_offsets, 0x6},
				patch_region{mp::eax_healing_offsets, 0x5},
				patch_region{mp::eax_split_healing_offsets, 0x5},
				patch_region{mp::int2d_breakpoint_offsets, 0x7},
			};

			static const std::array<patch_region, 8> sp_regions
			{
				patch_region{sp::big_intact_integrity_offsets, 0xA},
				patch_region{sp::big_split_integrity_offsets, 0x5},
				patch_region{sp::intact_integrity_offsets, 0x7},
				patch_region{empty_offsets, 0x5},
				patch_region{sp::al_healing_offsets, 0x6},
				patch_region{sp::eax_healing_offsets, 0x5},
				patch_region{sp::eax_split_healing_offsets, 0x5},
				patch_region{sp::int2d_breakpoint_offsets, 0x7},
			};

			return game::environment::is_mp() ? mp_regions : sp_regions;
		}

		void* find_next_block_address(void* start)
		{
			ud_t ud_obj;
			ud_init(&ud_obj);
			ud_set_mode(&ud_obj, 64);
			ud_set_pc(&ud_obj, reinterpret_cast<uint64_t>(start));
			// Scan up to 512 bytes forward. Arxan obfuscation can push the LEA quite far down.
			ud_set_input_buffer(&ud_obj, static_cast<uint8_t*>(start), 512);

			while (ud_disassemble(&ud_obj))
			{
				if (ud_obj.mnemonic == UD_Ilea)
				{
					const auto& op = ud_obj.operand[1];
					if (op.type == UD_OP_MEM && op.base == UD_R_RIP)
					{
						int64_t offset = 0;
						switch (op.offset) {
						case 8: offset = op.lval.sbyte; break;
						case 16: offset = op.lval.sword; break;
						case 32: offset = op.lval.sdword; break;
						}
						return reinterpret_cast<void*>(ud_obj.pc + offset);
					}
				}
				else if (ud_obj.mnemonic == UD_Ijmp)
				{
					const auto& op = ud_obj.operand[0];
					if (op.type == UD_OP_JIMM)
					{
						int64_t offset = 0;
						switch (op.size) {
						case 8: offset = op.lval.sbyte; break;
						case 16: offset = op.lval.sword; break;
						case 32: offset = op.lval.sdword; break;
						}
						return reinterpret_cast<void*>(ud_obj.pc + offset);
					}
				}
			}

			return nullptr;
		}

		bool overlaps_region(const uint64_t heal_start, const uint64_t heal_end, const patch_region& region)
		{
			for (const auto patched_address : region.offsets)
			{
				const auto patch_start = game::relocate(patched_address);
				const auto patch_end = patch_start + region.size;

				// [heal_start, heal_end) overlaps [patch_start, patch_end)
				if (heal_start < patch_end && heal_end > patch_start)
				{
					return true;
				}
			}

			return false;
		}

		bool overlaps_dynamic_region(const uint64_t heal_start, const uint64_t heal_end)
		{
			std::lock_guard<std::mutex> lock(active_patches_mutex);
			for (const auto& patch : active_patches)
			{
				if (heal_start < patch.end && heal_end > patch.start)
				{
					return true;
				}
			}
			return false;
		}

		bool allow_code_healing(void* heal_location, const uint32_t patch_length)
		{
			const auto heal_start = reinterpret_cast<uint64_t>(heal_location);
			const auto heal_end = heal_start + patch_length;

#ifdef PRECOMPUTED
			for (const auto& region : current_regions())
			{
				if (overlaps_region(heal_start, heal_end, region))
				{
#ifdef ARXAN_DEBUG
					OutputDebugStringA(utils::string::va("Blocked code healing at: %llX for size: %X\n", game::derelocate(heal_start), patch_length));
#endif
					return false;
				}
			}
#else
			if (overlaps_dynamic_region(heal_start, heal_end))
			{
#ifdef ARXAN_DEBUG
				OutputDebugStringA(utils::string::va("Blocked code healing at: %llX for size: %X\n", game::derelocate(heal_start), patch_length));
#else
				// LOG("Arxan/CodeHealing", INFO, "Blocked code healing at: {:X} for size: {:X}", game::derelocate(heal_start), patch_length);
#endif
				return false;
			}
#endif

			return true;
		}

		void patch_healing_code_sections_function_al(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);

			static const auto stub = utils::hook::assemble([](utils::hook::assembler& a)
			{
				a.pushad64();

				const auto skip_update = a.newLabel();

				a.mov(rcx, rdx); // rdx = destination pointer
				a.mov(edx, 1); // length = 1 byte (size of al)
				a.call_aligned(allow_code_healing);

				a.test(al, al);
				a.jz(skip_update);

				a.popad64();

				// Original instructions we overwrite:
				// mov [rdx], al
				// add dword ptr [rbp+20h], 0FFFFFFFFh
				a.mov(byte_ptr(rdx), al);
				a.add(dword_ptr(rbp, 0x20), -1);
				a.ret();

				a.bind(skip_update);
				a.popad64();

				// Skip overwrite but decrease counter
				a.add(dword_ptr(rbp, 0x20), -1);
				a.ret();
			});

			// Call overwrites 5 bytes, we nop 1 extra byte and mimic the needed instructions in our asm stub.
			utils::hook::nop(game_address, 6);
			utils::hook::call(game_address, stub);
		}

		void patch_healing_code_sections_function_eax(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);

			static const auto stub = utils::hook::assemble([](utils::hook::assembler& a)
			{
				a.pushad64();

				const auto skip_update = a.newLabel();

				a.mov(rcx, rdx); // rdx = destination pointer
				a.mov(edx, 4); // length = 4 bytes (size of eax)
				a.call_aligned(allow_code_healing);

				a.test(al, al);
				a.jz(skip_update);

				a.popad64();

				// Original instructions we overwrite:
				// mov [rdx], eax
				// mov eax, [rbp+20h]
				a.mov(dword_ptr(rdx), eax);
				a.mov(eax, dword_ptr(rbp, 0x20));
				a.ret();

				a.bind(skip_update);
				a.popad64();

				// Skip overwrite but reload original eax value
				a.mov(eax, dword_ptr(rbp, 0x20));
				a.ret();
			});

			utils::hook::call(game_address, stub);
		}

		void patch_healing_code_sections_function_eax_split(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);
			const auto next_block = find_next_block_address(address);

			if (!next_block)
			{
				LOG("Arxan/CodeHealing", ERROR, "Failed to find next block for split eax healing function at 0x{:X}", game_address);
				return;
			}

			const auto stub = utils::hook::assemble([next_block](utils::hook::assembler& a)
			{
				// Original instructions we overwrite/skip:
				// mov rdx, [rbp+10h]
				// mov eax, [rax]
				a.mov(rdx, qword_ptr(rbp, 0x10));
				a.mov(eax, dword_ptr(rax));

				// Our code
				a.pushad64();

				const auto skip_update = a.newLabel();

				a.mov(rcx, rdx); // rdx = destination pointer
				a.mov(edx, 4); // length = 4 bytes (size of eax)
				a.call_aligned(allow_code_healing);

				a.test(al, al);
				a.jz(skip_update);

				a.popad64();

				// Overwrite destination with eax value like original code
				a.mov(dword_ptr(rdx), eax);
				a.add(rsp, 8); // Remove return address from stack
				a.jmp(next_block);

				a.bind(skip_update);
				a.popad64();
				a.add(rsp, 8); // Remove return address from stack
				a.jmp(next_block);
			});

			utils::hook::call(game_address, stub);
		}

		void patch_code_healing_precomputed()
		{
			const auto& patches = current_patches();

			for (const auto offset : patches.al_healing)
			{
				patch_healing_code_sections_function_al(reinterpret_cast<void*>(game::relocate(offset)));
			}

			for (const auto offset : patches.eax_healing)
			{
				patch_healing_code_sections_function_eax(reinterpret_cast<void*>(game::relocate(offset)));
			}

			for (const auto offset : patches.eax_split_healing)
			{
				patch_healing_code_sections_function_eax_split(reinterpret_cast<void*>(game::relocate(offset)));
			}
		}

		void search_and_patch_code_healing()
		{
			const auto al_healing_results = "88 02 83 45 20 FF"_sig;
			LOG("Arxan/CodeHealing", INFO, "Found {} matches for 'al' code healing", al_healing_results.size());
			for (auto* i : al_healing_results)
			{
				patch_healing_code_sections_function_al(i);
			}

			const auto eax_healing_results = "89 02 8B 45 20"_sig;
			LOG("Arxan/CodeHealing", INFO, "Found {} matches for 'eax' code healing", eax_healing_results.size());
			for (auto* i : eax_healing_results)
			{
				patch_healing_code_sections_function_eax(i);
			}

			const auto eax_split_healing_results = "48 8B 55 10 8B 00 89 02 ? ? ? 24 F8"_sig;
			LOG("Arxan/CodeHealing", INFO, "Found {} matches for 'split eax' code healing", eax_split_healing_results.size());
			for (auto* i : eax_split_healing_results)
			{
				patch_healing_code_sections_function_eax_split(i);
			}
		}

		void patch_code_healing()
		{
#ifdef PRECOMPUTED
			patch_code_healing_precomputed();
#else
			search_and_patch_code_healing();
#endif
		}
	}

	struct component final : generic_component
	{
	public:
		void post_thread_setup() override
		{
			patch_code_healing();
		}

		component_priority priority() const override
		{
			return component_priority::arxan;
		}
	};
}

// REGISTER_COMPONENT(arxan::code_healing::component)
