#include "common.hpp"
#include <loader/component_loader.hpp>

#include "integrity_locations.hpp"
#include "game/game.hpp"

#include <utils/hook.hpp>
#include <utils/string.hpp>

namespace arxan::code_healing
{
	void register_patch(uint64_t address, size_t size);
}

namespace arxan::integrity
{
	namespace
	{
		const std::vector<std::pair<uint8_t*, size_t>>& get_text_sections()
		{
			static const std::vector<std::pair<uint8_t*, size_t>> text = []
			{
				std::vector<std::pair<uint8_t*, size_t>> texts{};

				const utils::nt::library game{};
				for (const auto& section : game.get_section_headers())
				{
					if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
					{
						texts.emplace_back(game.get_ptr() + section->VirtualAddress, section->Misc.VirtualSize);
					}
				}

				return texts;
			}();

			return text;
		}

		bool is_in_texts(const uint64_t addr)
		{
			const auto& texts = get_text_sections();
			for (const auto& text : texts)
			{
				const auto start = reinterpret_cast<ULONG_PTR>(text.first);
				if (addr >= start && addr <= (start + text.second))
				{
					return true;
				}
			}

			return false;
		}

		bool is_in_texts(const void* addr)
		{
			return is_in_texts(reinterpret_cast<uint64_t>(addr));
		}

		struct integrity_handler_context
		{
			uint32_t* computed_checksum;
			uint32_t* original_checksum;
		};

		bool is_on_stack(uint8_t* stack_frame, const void* pointer)
		{
			const auto stack_value = reinterpret_cast<uint64_t>(stack_frame);
			const auto pointer_value = reinterpret_cast<uint64_t>(pointer);

			const auto diff = static_cast<int64_t>(stack_value - pointer_value);
			return std::abs(diff) < 0x10000; // Increased to 64KB for distant stack frames
		}

		bool is_in_game_module(const void* addr)
		{
			static const utils::nt::library game{};
			return game.is_address_in_range(reinterpret_cast<std::uintptr_t>(addr));
		}

		bool is_handler_context(uint8_t* stack_frame, const uint32_t computed_checksum, const uint32_t frame_offset, const uint32_t index)
		{
			const auto* potential_context = reinterpret_cast<integrity_handler_context*>(stack_frame + frame_offset);

			// Avoid page faults by verifying address is readable
			if (IsBadReadPtr(potential_context, sizeof(integrity_handler_context)))
			{
				return false;
			}

			if (IsBadReadPtr(&potential_context->computed_checksum[index], sizeof(uint32_t)) ||
				IsBadReadPtr(&potential_context->original_checksum[index], sizeof(uint32_t)))
			{
				return false;
			}

			return is_on_stack(stack_frame, &potential_context->computed_checksum[index])
				&& potential_context->computed_checksum[index] == computed_checksum
				&& is_in_game_module(&potential_context->original_checksum[index]);
		}

		integrity_handler_context* search_handler_context(uint8_t* stack_frame, const uint32_t computed_checksum, const uint32_t index)
		{
			for (uint32_t frame_offset = 0; frame_offset < 0x1000; frame_offset += 8)
			{
				if (is_handler_context(stack_frame, computed_checksum, frame_offset, index))
				{
					return reinterpret_cast<integrity_handler_context*>(stack_frame + frame_offset);
				}
			}

			return nullptr;
		}

		uint32_t adjust_integrity_checksum(const uint64_t return_address, uint8_t* stack_frame, const uint32_t current_checksum, const uint32_t index)
		{
			const auto handler_address = game::derelocate(return_address - 5);
			const auto* context = search_handler_context(stack_frame, current_checksum, index);

			if (!context)
			{
				LOG("Arxan/Integrity", WARN, "No frame offset found for: {:X} (checksum: {:X}, index: {})", handler_address, current_checksum, index);
				return current_checksum;
			}

			const auto correct_checksum = context->original_checksum[index];
			context->computed_checksum[index] = correct_checksum;

#ifdef ARXAN_DEBUG
			if (current_checksum != correct_checksum)
			{
				OutputDebugStringA(utils::string::va("Adjusting checksum (%llX): %X -> %X\n", handler_address,
					current_checksum, correct_checksum));
			}
#endif

			return correct_checksum;
		}

		void patch_intact_basic_block_integrity_check(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);
			constexpr auto inst_len = 3;

			const auto next_inst_addr = game_address + inst_len;
			const auto next_inst = *reinterpret_cast<uint32_t*>(next_inst_addr);

			if ((next_inst & 0xFF00FFFF) != 0xFF004583)
			{
				LOG("Arxan/Integrity", ERROR, "Unable to patch intact basic block: {:X}", game_address);
				return;
			}

			const auto other_frame_offset = static_cast<uint8_t>(next_inst >> 16);
			static const auto stub = utils::hook::assemble([](utils::hook::assembler& a)
			{
				a.push(rax);

				a.mov(rax, qword_ptr(rsp, 8));
				a.sub(rax, 2); // Skip the push we inserted

				a.push(rax);
				a.pushad64();

				a.mov(r8, qword_ptr(rsp, 0x88));
				a.mov(rcx, rax);
				a.mov(rdx, rbp);
				a.mov(r9, qword_ptr(rsp, 0x98)); // Extract other_frame_offset from stack
				a.mov(r9d, dword_ptr(rbp, r9)); // value at rbp+offset -> checksum array offset
				a.call_aligned(adjust_integrity_checksum);

				a.mov(qword_ptr(rsp, 0x78), rax);

				a.popad64();
				a.pop(rax);

				a.add(rsp, 8);

				a.mov(dword_ptr(rdx, rcx, 4), eax);

				a.pop(rax); // return addr
				a.xchg(rax, qword_ptr(rsp)); // switch with push

				a.add(dword_ptr(rbp, rax), 0xFFFFFFFF);

				a.mov(rax, dword_ptr(rdx, rcx, 4)); // restore rax

				a.ret();
			});

			// push other_frame_offset
			utils::hook::set<uint16_t>(game_address, static_cast<uint16_t>(0x6A | (other_frame_offset << 8)));
			utils::hook::call(game_address + 2, stub);
			arxan::code_healing::register_patch(game_address, 7);
		}

		void patch_big_intact_basic_block_integrity_check(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);
			constexpr auto inst_len = 3;

			const auto next_inst_addr = game_address + inst_len;
			const auto* p = reinterpret_cast<const uint8_t*>(next_inst_addr);

			if (!(p[0] == 0x83 && p[1] == 0x85 && p[6] == 0xFF))
			{
				LOG("Arxan/Integrity", ERROR, "Unable to patch intact basic block: {:X}", game_address);
				return;
			}

			const auto other_frame_offset = *reinterpret_cast<uint32_t*>(next_inst_addr + 2);
			static const auto stub = utils::hook::assemble([](utils::hook::assembler& a)
			{
				a.push(rax);

				a.mov(rax, qword_ptr(rsp, 8));
				a.sub(rax, 5); // Skip the push we inserted

				a.push(rax);
				a.pushad64();

				a.mov(r8, qword_ptr(rsp, 0x88));
				a.mov(rcx, rax);
				a.mov(rdx, rbp);
				a.mov(r9, qword_ptr(rsp, 0x98));          // Extract other_frame_offset from stack
				a.mov(r9d, dword_ptr(rbp, r9));         // value at rbp+offset -> checksum array offset
				a.call_aligned(adjust_integrity_checksum);

				a.mov(qword_ptr(rsp, 0x78), rax);

				a.popad64();
				a.pop(rax);

				a.add(rsp, 8);

				a.mov(dword_ptr(rdx, rcx, 4), eax);

				a.pop(rax); // return addr
				a.xchg(rax, qword_ptr(rsp)); // switch with push

				a.add(dword_ptr(rbp, rax), 0xFFFFFFFF);

				a.mov(rax, dword_ptr(rdx, rcx, 4)); // restore rax

				a.ret();
			});

			// push other_frame_offset
			utils::hook::set<uint8_t>(game_address, 0x68);
			utils::hook::set<uint32_t>(game_address + 1, other_frame_offset);

			utils::hook::call(game_address + 5, stub);
			arxan::code_healing::register_patch(game_address, 10);
		}

#include <udis86.h>

		void* find_jump_target(void* start)
		{
			ud_t ud_obj;
			ud_init(&ud_obj);
			ud_set_mode(&ud_obj, 64);
			ud_set_pc(&ud_obj, reinterpret_cast<uint64_t>(start));
			ud_set_input_buffer(&ud_obj, static_cast<uint8_t*>(start), 128);

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

				if (ud_obj.mnemonic == UD_Iret || ud_obj.mnemonic == UD_Iint3)
				{
					break;
				}
			}

			return nullptr;
		}


		void patch_split_basic_block_integrity_check(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);
			const auto next_inst_addr = game_address + 3;

			const auto jump_target = find_jump_target(reinterpret_cast<void*>(next_inst_addr));
			if (!jump_target)
			{
				std::string hex_dump;
				for (int i = 0; i < 32; ++i)
				{
					hex_dump += utils::string::va("%02X ", *(reinterpret_cast<uint8_t*>(game_address) + i));
				}
				LOG("Arxan/Integrity", ERROR, "Unable to find jump target for split basic block: {:X}. Dump: {}", game_address, hex_dump);
				return;
			}

			const auto stub = utils::hook::assemble([jump_target](utils::hook::assembler& a)
			{
				a.push(rax);

				a.mov(rax, qword_ptr(rsp, 8));
				a.push(rax);

				a.pushad64();

				a.mov(r8, qword_ptr(rsp, 0x88));
				a.mov(rcx, rax);
				a.mov(rdx, qword_ptr(rsp, 0x98)); // Use original RSP instead of RBP as frame pointer
				a.mov(r9d, dword_ptr(rsp, 0x70)); // original RCX is the correct checksum array index
				a.call_aligned(adjust_integrity_checksum);

				a.mov(qword_ptr(rsp, 0x78), rax);

				a.popad64();
				a.pop(rax);

				a.add(rsp, 8);

				a.mov(dword_ptr(rdx, rcx, 4), eax);

				a.add(rsp, 8);

				a.jmp(jump_target);
			});

			utils::hook::call(game_address, stub);
			arxan::code_healing::register_patch(game_address, 5);
		}

		void patch_big_split_basic_block_integrity_check(void* address)
		{
			const auto game_address = reinterpret_cast<uint64_t>(address);
			const auto next_inst_addr = game_address + 3;

			const auto jump_target = find_jump_target(reinterpret_cast<void*>(next_inst_addr));
			if (!jump_target)
			{
				LOG("Arxan/Integrity", ERROR, "Unable to find jump target for split basic block: {:X}", game_address);
				return;
			}

			const auto other_frame_offset = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(jump_target) + 2);
			const auto stub = utils::hook::assemble([jump_target, other_frame_offset](utils::hook::assembler& a)
			{
				a.push(rax);

				a.mov(rax, qword_ptr(rsp, 8));
				a.push(rax);

				a.pushad64();

				a.mov(r8, qword_ptr(rsp, 0x88));
				a.mov(rcx, rax);
				a.mov(rdx, qword_ptr(rsp, 0x98)); // Use original RSP instead of RBP as frame pointer
				a.mov(r9, other_frame_offset);          // other_frame_offset
				a.mov(r9d, dword_ptr(rbp, r9));         // value at rbp+offset -> checksum array offset
				a.call_aligned(adjust_integrity_checksum);

				a.mov(qword_ptr(rsp, 0x78), rax);

				a.popad64();
				a.pop(rax);

				a.add(rsp, 8);

				a.mov(dword_ptr(rdx, rcx, 4), eax);

				a.add(rsp, 8);

				a.jmp(jump_target);
			});

			utils::hook::call(game_address, stub);
			arxan::code_healing::register_patch(game_address, 5);
		}

		void patch_integrity_checks_precomputed()
		{
			if (game::environment::is_mp())
			{
				for (const auto offset : mp::intact_integrity_offsets)
				{
					patch_intact_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}

				for (const auto offset : mp::big_intact_integrity_offsets)
				{
					patch_big_intact_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}

				for (const auto offset : mp::split_integrity_offsets)
				{
					patch_split_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}

				for (const auto offset : mp::big_split_integrity_offsets)
				{
					patch_big_split_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}
			}
			else
			{
				for (const auto offset : sp::intact_integrity_offsets)
				{
					patch_intact_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}

				for (const auto offset : sp::big_intact_integrity_offsets)
				{
					patch_big_intact_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}

				for (const auto offset : sp::big_split_integrity_offsets)
				{
					patch_big_split_basic_block_integrity_check(reinterpret_cast<void*>(game::relocate(offset)));
				}
			}	
		}

		void search_and_patch_integrity_checks()
		{
			const auto all_movs = "89 04 8A"_sig;
			LOG("Arxan/Integrity", INFO, "Found {} potential integrity checks (89 04 8A)", all_movs.size());

			int intact_count = 0;
			int big_intact_count = 0;
			int split_count = 0;
			int big_split_count = 0;

			for (auto* i : all_movs)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);

				// Check intact: 89 04 8A 83 45 XX FF
				if (ptr[3] == 0x83 && ptr[4] == 0x45 && ptr[6] == 0xFF)
				{
					patch_intact_basic_block_integrity_check(i);
					intact_count++;
					continue;
				}

				// Check big_intact: 89 04 8A 83 85 XX XX XX XX FF
				if (ptr[3] == 0x83 && ptr[4] == 0x85 && ptr[9] == 0xFF)
				{
					patch_big_intact_basic_block_integrity_check(i);
					big_intact_count++;
					continue;
				}

				// It's not intact, check if it's a split by finding the jump target
				auto* jump_target = reinterpret_cast<uint8_t*>(find_jump_target(reinterpret_cast<void*>(reinterpret_cast<uint64_t>(i) + 3)));
				if (jump_target)
				{
					// Check split jump target: 83 45 XX FF
					if (jump_target[0] == 0x83 && jump_target[1] == 0x45 && jump_target[3] == 0xFF)
					{
						patch_split_basic_block_integrity_check(i);
						split_count++;
						continue;
					}

					// Check big_split jump target: 83 85 XX XX XX XX FF
					if (jump_target[0] == 0x83 && jump_target[1] == 0x85 && jump_target[6] == 0xFF)
					{
						patch_big_split_basic_block_integrity_check(i);
						big_split_count++;
						continue;
					}
				}
				std::string bytes_str;
				for (int j = 0; j < 15; ++j) {
					bytes_str += std::format("{:02X} ", ptr[3 + j]);
				}
				LOG("Arxan/Integrity", INFO, "Unpatched check at {:X}. Bytes after 89 04 8A: {}", game::derelocate(i), bytes_str);
			}

			LOG("Arxan/Integrity", INFO, "Patched {} intact, {} big intact, {} split, {} big split", intact_count, big_intact_count, split_count, big_split_count);
		}

		void patch_checksum_comparisons()
		{
			// Dynamic XOR table comparison patcher
			const auto candidate_xor = "8B ? ? 33 ? ?"_sig;
			auto xor_table_compare_count = 0;
			for (auto* i : candidate_xor)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue; // mod=00/01/10, rm=100 (SIB)
				if ((ptr[2] & 0xC0) != 0x80) continue; // scale=10 (*4)
				if ((ptr[4] & 0xC7) != 0x04) continue;
				if ((ptr[5] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t xor_reg = (ptr[4] >> 3) & 7;
				if (mov_reg != xor_reg) continue;

				uint8_t xor_reg_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				// Patch the MOV to XOR reg, reg and NOP the rest
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_reg_modrm);
				utils::hook::nop(ptr + 2, 4);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 6);
				xor_table_compare_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic XOR table comparisons", xor_table_compare_count);

			// Dynamic SUB table comparison patcher
			const auto candidate_sub = "8B ? ? 2B ? ?"_sig;
			auto sub_table_compare_count = 0;
			for (auto* i : candidate_sub)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[4] & 0xC7) != 0x04) continue;
				if ((ptr[5] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t sub_reg = (ptr[4] >> 3) & 7;
				if (mov_reg != sub_reg) continue;

				uint8_t xor_reg_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_reg_modrm);
				utils::hook::nop(ptr + 2, 4);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 6);
				sub_table_compare_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic SUB comparisons", sub_table_compare_count);

			// Dynamic NEG+ADD table comparison patcher (Variant 2)
			const auto candidate_neg_add = "8B ? ? F7 ? 03 ? ?"_sig;
			auto neg_add_count = 0;
			for (auto* i : candidate_neg_add)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t neg_modrm = ptr[4];
				if (neg_modrm != (0xC0 | (3 << 3) | mov_reg)) continue;

				if ((ptr[6] & 0xC7) != 0x04) continue;
				if ((ptr[7] & 0xC0) != 0x80) continue;
				uint8_t add_reg = (ptr[6] >> 3) & 7;
				if (add_reg != mov_reg) continue;

				uint8_t xor_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_modrm);
				utils::hook::nop(ptr + 2, 6);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 8);
				neg_add_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic NEG+ADD comparisons", neg_add_count);

			// Dynamic CMP table comparison patcher (Variant 3)
			const auto candidate_cmp = "8B ? ? 8B ? ? 3B ?"_sig;
			auto cmp_table_compare_count = 0;
			for (auto* i : candidate_cmp)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[4] & 0xC7) != 0x04) continue;
				if ((ptr[5] & 0xC0) != 0x80) continue;
				if ((ptr[7] & 0xC0) != 0xC0) continue; // Register to register comparison

				uint8_t mov1_reg = (ptr[1] >> 3) & 7;
				uint8_t mov2_reg = (ptr[4] >> 3) & 7;

				uint8_t cmp_reg1 = (ptr[7] >> 3) & 7;
				uint8_t cmp_reg2 = ptr[7] & 7;

				if (mov1_reg != cmp_reg1 || mov2_reg != cmp_reg2) continue;

				uint8_t cmp_reg1_reg1_modrm = 0xC0 | (cmp_reg1 << 3) | cmp_reg1;
				utils::hook::set<uint8_t>(ptr + 6, 0x3B);
				utils::hook::set<uint8_t>(ptr + 7, cmp_reg1_reg1_modrm);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr + 6), 2);
				cmp_table_compare_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic CMP comparisons", cmp_table_compare_count);

			// Dynamic CMP table comparison patcher (Variant 4: 1 MOV)
			const auto candidate_cmp_1mov = "8B ? ? 3B ? ?"_sig;
			auto cmp_1mov_count = 0;
			for (auto* i : candidate_cmp_1mov)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[4] & 0xC7) != 0x04) continue;
				if ((ptr[5] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t cmp_reg = (ptr[4] >> 3) & 7;
				if (mov_reg != cmp_reg) continue;

				uint8_t cmp_reg_reg_modrm = 0xC0 | (cmp_reg << 3) | cmp_reg;
				utils::hook::set<uint8_t>(ptr + 3, 0x3B);
				utils::hook::set<uint8_t>(ptr + 4, cmp_reg_reg_modrm);
				utils::hook::nop(ptr + 5, 1);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr + 3), 3);
				cmp_1mov_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic CMP (1 MOV) comparisons", cmp_1mov_count);

			// Dynamic CMP table comparison patcher (Variant 5: CMP [mem], reg)
			const auto candidate_cmp_mem_reg = "8B ? ? 39 ? ?"_sig;
			auto cmp_mem_reg_count = 0;
			for (auto* i : candidate_cmp_mem_reg)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x04) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[4] & 0xC7) != 0x04) continue;
				if ((ptr[5] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t cmp_reg = (ptr[4] >> 3) & 7;
				if (mov_reg != cmp_reg) continue;

				uint8_t cmp_reg_reg_modrm = 0xC0 | (cmp_reg << 3) | cmp_reg;
				utils::hook::set<uint8_t>(ptr + 3, 0x39);
				utils::hook::set<uint8_t>(ptr + 4, cmp_reg_reg_modrm);
				utils::hook::nop(ptr + 5, 1);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr + 3), 3);
				cmp_mem_reg_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic CMP [mem], reg comparisons", cmp_mem_reg_count);

			// Dynamic XOR table comparison patcher (disp8)
			const auto candidate_xor_disp8 = "8B ? ? ? 33 ? ? ?"_sig;
			auto xor_disp8_count = 0;
			for (auto* i : candidate_xor_disp8)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x44) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[5] & 0xC7) != 0x44) continue;
				if ((ptr[6] & 0xC0) != 0x80) continue;
				
				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t xor_reg = (ptr[5] >> 3) & 7;
				if (mov_reg != xor_reg) continue;

				uint8_t xor_reg_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_reg_modrm);
				utils::hook::nop(ptr + 2, 6);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 8);
				xor_disp8_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic XOR (disp8) comparisons", xor_disp8_count);

			// Dynamic SUB table comparison patcher (disp8)
			const auto candidate_sub_disp8 = "8B ? ? ? 2B ? ? ?"_sig;
			auto sub_disp8_count = 0;
			for (auto* i : candidate_sub_disp8)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x44) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[5] & 0xC7) != 0x44) continue;
				if ((ptr[6] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t sub_reg = (ptr[5] >> 3) & 7;
				if (mov_reg != sub_reg) continue;

				uint8_t xor_reg_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_reg_modrm);
				utils::hook::nop(ptr + 2, 6);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 8);
				sub_disp8_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic SUB (disp8) comparisons", sub_disp8_count);

			// Dynamic CMP table comparison patcher (disp8)
			const auto candidate_cmp_disp8 = "8B ? ? ? 3B ? ? ?"_sig;
			auto cmp_disp8_count = 0;
			for (auto* i : candidate_cmp_disp8)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x44) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[5] & 0xC7) != 0x44) continue;
				if ((ptr[6] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t cmp_reg = (ptr[5] >> 3) & 7;
				if (mov_reg != cmp_reg) continue;

				uint8_t cmp_reg_reg_modrm = 0xC0 | (cmp_reg << 3) | cmp_reg;
				utils::hook::set<uint8_t>(ptr + 4, 0x3B);
				utils::hook::set<uint8_t>(ptr + 5, cmp_reg_reg_modrm);
				utils::hook::nop(ptr + 6, 2);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr + 4), 4);
				cmp_disp8_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic CMP (disp8) comparisons", cmp_disp8_count);

			// Dynamic NEG+ADD table comparison patcher (disp8)
			const auto candidate_neg_add_disp8 = "8B ? ? ? F7 ? 03 ? ? ?"_sig;
			auto neg_add_disp8_count = 0;
			for (auto* i : candidate_neg_add_disp8)
			{
				auto* ptr = reinterpret_cast<uint8_t*>(i);
				if ((ptr[1] & 0xC7) != 0x44) continue;
				if ((ptr[2] & 0xC0) != 0x80) continue;
				if ((ptr[5] & 0xF8) != 0xD8) continue;
				if ((ptr[7] & 0xC7) != 0x44) continue;
				if ((ptr[8] & 0xC0) != 0x80) continue;

				uint8_t mov_reg = (ptr[1] >> 3) & 7;
				uint8_t neg_reg = ptr[5] & 7;
				uint8_t add_reg = (ptr[7] >> 3) & 7;
				if (mov_reg != neg_reg || mov_reg != add_reg) continue;

				uint8_t xor_reg_reg_modrm = 0xC0 | (mov_reg << 3) | mov_reg;
				
				utils::hook::set<uint8_t>(ptr, 0x33);
				utils::hook::set<uint8_t>(ptr + 1, xor_reg_reg_modrm);
				utils::hook::nop(ptr + 2, 8);
				arxan::code_healing::register_patch(reinterpret_cast<uint64_t>(ptr), 10);
				neg_add_disp8_count++;
			}
			LOG("Arxan/Integrity", INFO, "Patched {} dynamic NEG+ADD (disp8) comparisons", neg_add_disp8_count);
		}

		void patch_integrity_checks()
		{
#ifdef PRECOMPUTED
			patch_integrity_checks_precomputed();
#else
			search_and_patch_integrity_checks();
#endif
			patch_checksum_comparisons();
		}
	}

	struct component final : generic_component
	{
	public:
		void post_thread_setup() override
		{
			patch_integrity_checks();
		}

		component_priority priority() const override
		{
			return component_priority::arxan;
		}
	};
}

// REGISTER_COMPONENT(arxan::integrity::component)
