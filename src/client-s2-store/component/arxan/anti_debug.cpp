#include "common.hpp"
#include <loader/component_loader.hpp>

#pragma comment(lib, "ntdll.lib")

#include "component/scheduler.hpp"
#include "game/game.hpp"

#include <utils/hook.hpp>
#include <utils/string.hpp>
#include <MinHook.h>
#include "breakpoints.hpp"
#include "../exception_filter.hpp"

PVOID g_veh_handle = nullptr;

#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 30
#define ProcessDebugFlags 31
#define ProcessImageFileNameWin32 43

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

namespace arxan::anti_debug
{
	namespace
	{
		typedef enum _THREADINFOCLASS
		{
			ThreadBasicInformation = 0,
			ThreadHideFromDebugger = 17,
		} THREADINFOCLASS;

		utils::hook::detour nt_create_section_hook;
		utils::hook::detour nt_close_hook;
		utils::hook::detour nt_query_system_information_hook;
		utils::hook::detour nt_query_information_process_hook;
		utils::hook::detour nt_set_information_thread_hook;
		utils::hook::detour nt_query_information_thread_hook;
		utils::hook::detour nt_create_thread_ex_hook;
		utils::hook::detour create_mutex_ex_a_hook;
		utils::hook::detour create_thread_hook;
		utils::hook::detour get_thread_context_hook;
		utils::hook::detour check_remote_debugger_present_hook;
		utils::hook::detour enum_windows_hook;

		void* original_first_tls_callback = nullptr;

		void** get_tls_callbacks()
		{
			const utils::nt::library game{};
			const auto& entry = game.get_optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
			if (!entry.VirtualAddress || !entry.Size)
			{
				return nullptr;
			}

			const auto* tls_dir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(game.get_ptr() + entry.VirtualAddress);
			return reinterpret_cast<void**>(tls_dir->AddressOfCallBacks);
		}

		void disable_tls_callbacks()
		{
			auto* tls_callbacks = get_tls_callbacks();
			if (!tls_callbacks)
			{
				return;
			}

			original_first_tls_callback = tls_callbacks[0];
			utils::hook::set(&tls_callbacks[0], nullptr);
		}

		void restore_tls_callbacks()
		{
			auto* tls_callbacks = get_tls_callbacks();
			if (!tls_callbacks)
			{
				return;
			}

			utils::hook::set(&tls_callbacks[0], original_first_tls_callback);
		}

		bool is_valid_thread_handle(HANDLE h)
		{
			if (h == reinterpret_cast<HANDLE>(-2)) // NtCurrentThread
			{
				return true;
			}


			DWORD tid = GetThreadId(h);
			if (tid == 0)
			{
				return false;
			}

			return true;
		}

		void hide_being_debugged()
		{
			auto* const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
			peb->BeingDebugged = false;
			*reinterpret_cast<PDWORD>(LPSTR(peb) + 0xBC) &= ~0x70;

			auto* const heap = *reinterpret_cast<PVOID*>(LPSTR(peb) + 0x30);
			if (heap != nullptr)
			{
				*reinterpret_cast<PDWORD>(LPSTR(heap) + 0x70) = 2;   // Force to HEAP_GROWABLE only
				*reinterpret_cast<PDWORD>(LPSTR(heap) + 0x74) = 0;   // ForceFlags = 0
			}
		}

		void restore_debug_functions()
		{
			static const char* functions[] = {
				"DbgBreakPoint",
				"DbgUserBreakPoint",
				"DbgUiConnectToDbg",
				"DbgUiContinue",
				"DbgUiConvertStateChangeStructure",
				"DbgUiDebugActiveProcess",
				"DbgUiGetThreadDebugObject",
				"DbgUiIssueRemoteBreakin",
				"DbgUiRemoteBreakin",
				"DbgUiSetThreadDebugObject",
				"DbgUiStopDebugging",
				"DbgUiWaitStateChange",
				"DbgPrintReturnControlC",
				"DbgPrompt",
			};

			using buffer = uint8_t[15];
			static buffer buffers[ARRAYSIZE(functions)] = {};
			static bool loaded = false;

			const utils::nt::library ntdll("ntdll.dll");

			for (auto i = 0u; i < ARRAYSIZE(functions); ++i)
			{
				const auto func = ntdll.get_proc<void*>(functions[i]);
				if (!func)
				{
					continue;
				}

				if (!loaded)
				{
					memcpy(buffers[i], func, sizeof(buffer));
				}
				else
				{
					utils::hook::copy(func, buffers[i], sizeof(buffer));
				}
			}

			loaded = true;
		}


		HANDLE WINAPI create_thread_stub(const LPSECURITY_ATTRIBUTES thread_attributes, const SIZE_T stack_size,
			const LPTHREAD_START_ROUTINE start_address, const LPVOID parameter,
			const DWORD creation_flags,
			const LPDWORD thread_id)
		{
			if (utils::nt::library::get_by_address(start_address) != utils::nt::library{"d3d11.dll"})
			{
				restore_tls_callbacks();

				component_loader::post_unpack();
				component_loader::post_thread_setup();

				create_thread_hook.clear();
				return CreateThread(thread_attributes, stack_size, start_address, parameter, creation_flags,
					thread_id);
			}

			return create_thread_hook.invoke<HANDLE>(thread_attributes, stack_size, start_address, parameter,
				creation_flags, thread_id);
		}

		HANDLE create_mutex_ex_a_stub(const LPSECURITY_ATTRIBUTES attributes, const LPCSTR name, const DWORD flags,
			const DWORD access)
		{
			if (name == "$ IDA trusted_idbs"s || name == "$ IDA registry mutex $"s)
			{
				return nullptr;
			}

			return create_mutex_ex_a_hook.invoke<HANDLE>(attributes, name, flags, access);
		}

		bool remove_evil_keywords_from_string(const UNICODE_STRING& string)
		{
			static const std::wstring evil_keywords[] =
			{
				L"IDA",
				L"ida",
				L"HxD",
				L"cheatengine",
				L"Cheat Engine",
				L"x96dbg",
				L"x32dbg",
				L"x64dbg",
				L"Wireshark",
				L"DebugView",
				L"ReClass.NET (x64)",
				L"ReClass.NET",
			};

			if (!string.Buffer || string.Length == 0)
			{
				return false;
			}

			const size_t char_count = string.Length / sizeof(wchar_t);
			std::wstring_view path(string.Buffer, char_count);

			bool modified = false;
			for (const auto& keyword : evil_keywords)
			{
				while (true)
				{
					const auto pos = path.find(keyword);
					if (pos == std::wstring_view::npos)
					{
						break;
					}

					modified = true;

					for (size_t i = 0; i < keyword.size(); ++i)
					{
						string.Buffer[pos + i] = L'a';
					}
				}
			}

			return modified;
		}

		bool remove_evil_keywords_from_string(wchar_t* str, const size_t length)
		{
			if (!str || length == 0)
			{
				return false;
			}
				
			if (length > (std::numeric_limits<uint16_t>::max() / sizeof(wchar_t)))
			{
				return false;
			}

			UNICODE_STRING unicode_string{};
			unicode_string.Buffer = str;
			unicode_string.Length = static_cast<uint16_t>(length * sizeof(wchar_t));
			unicode_string.MaximumLength = unicode_string.Length;

			return remove_evil_keywords_from_string(unicode_string);
		}

		bool remove_evil_keywords_from_string(char* str, const size_t length)
		{
			std::string_view str_view(str, length);
			std::wstring wstr(str_view.begin(), str_view.end());

			if (!remove_evil_keywords_from_string(&wstr[0], wstr.size()))
			{
				return false;
			}

			const std::string regular_str(wstr.begin(), wstr.end());
			memcpy(str, regular_str.data(), length);

			return true;
		}

		int WINAPI get_window_text_a_stub(const HWND wnd, const LPSTR str, const int max_count)
		{
			std::wstring wstr{};
			wstr.resize(max_count);

			const auto res = GetWindowTextW(wnd, &wstr[0], max_count);
			if (res)
			{
				remove_evil_keywords_from_string(wstr.data(), res);

				const std::string regular_str(wstr.begin(), wstr.end());
				memset(str, 0, max_count);
				memcpy(str, regular_str.data(), res);
			}

			return res;
		}

		NTSTATUS NTAPI nt_query_system_information_stub(const SYSTEM_INFORMATION_CLASS system_information_class,
			const PVOID system_information,
			const ULONG system_information_length,
			const PULONG return_length)
		{
			const auto status = nt_query_system_information_hook.invoke<NTSTATUS>(
				system_information_class, system_information, system_information_length, return_length);

			if (NT_SUCCESS(status))
			{
				if (system_information_class == SystemProcessInformation && !utils::nt::is_shutdown_in_progress())
				{
					auto addr = static_cast<uint8_t*>(system_information);

					while (true)
					{
						const auto info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(addr);
						remove_evil_keywords_from_string(info->ImageName);

						if (!info->NextEntryOffset)
						{
							break;
						}

						addr = addr + info->NextEntryOffset;
					}
				}
			}

			return status;
		}

		NTSTATUS WINAPI nt_query_information_process_stub(const HANDLE handle, const PROCESSINFOCLASS info_class,
			const PVOID info,
			const ULONG info_length, const PULONG ret_length)
		{
			const auto status = nt_query_information_process_hook.invoke<NTSTATUS>(handle, info_class, info, info_length,
				ret_length);

			if (NT_SUCCESS(status))
			{
				if (info_class == ProcessDebugObjectHandle)
				{
					*static_cast<HANDLE*>(info) = nullptr;
					return static_cast<LONG>(0xC0000353);
				}
				else if (info_class == ProcessImageFileName || static_cast<int>(info_class) ==
					ProcessImageFileNameWin32)
				{
					remove_evil_keywords_from_string(*static_cast<UNICODE_STRING*>(info));
				}
				else if (info_class == ProcessDebugPort)
				{
					*static_cast<HANDLE*>(info) = nullptr;
				}
				else if (info_class == ProcessDebugFlags)
				{
					*static_cast<ULONG*>(info) = 1;
				}
			}

			return status;
		}

		NTSTATUS NTAPI nt_close_stub(const HANDLE handle)
		{
			char info[16];
			if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS(4), &info, 2, nullptr) >= 0 && size_t(handle) != 0x12345)
			{
				return nt_close_hook.invoke<NTSTATUS>(handle);
			}

			return STATUS_INVALID_HANDLE;
		}

		int WINAPI get_system_metrics_stub(const int index)
		{
			if (SM_REMOTESESSION == index)
			{
				return 0;
			}

			return GetSystemMetrics(index);
		}

		BOOL WINAPI get_thread_context_stub(const HANDLE thread_handle, const LPCONTEXT context)
		{
			const auto requested = context ? context->ContextFlags : 0;
			const auto result = get_thread_context_hook.invoke<BOOL>(thread_handle, context);

			if (result && context)
			{
				constexpr DWORD64 debug_flags = CONTEXT_DEBUG_REGISTERS;

				auto* source = _ReturnAddress();
				const auto game = utils::nt::library{};
				const auto source_module = utils::nt::library::get_by_address(source);

				// If the game is requesting debug registers, modify the context to hide them from the game
				if (source_module == game && (requested & debug_flags))
				{
					context->Dr0 = 0;
					context->Dr1 = 0;
					context->Dr2 = 0;
					context->Dr3 = 0;
					context->Dr6 = 0;
					context->Dr7 = 0;
				}
			}

			return result;
		}

		NTSTATUS NTAPI nt_set_information_thread_stub(HANDLE thread_handle,
			THREADINFOCLASS thread_information_class,
			PVOID thread_information,
			ULONG thread_information_length)
		{
			// The game uses ThreadHideFromDebugger to hide threads from the debugger
			if (thread_information_class == ThreadHideFromDebugger)
			{
				// The game verifies NtSetInformationThread integrity before actually hiding the thread.
				// It provides an invalid handle to NtSetInformationThread and expects STATUS_INVALID_HANDLE in return.
				if (!is_valid_thread_handle(thread_handle))
				{
					return STATUS_INVALID_HANDLE;
				}

				// Same for length, it must be 0
				if (thread_information_length != 0)
				{
					return STATUS_INFO_LENGTH_MISMATCH;
				}

				// If the parameters are correct, we can just return success without actually hiding the thread.
				return STATUS_SUCCESS;
			}

			return nt_set_information_thread_hook.invoke<NTSTATUS>(
				thread_handle,
				thread_information_class,
				thread_information,
				thread_information_length
			);
		}

		NTSTATUS NTAPI nt_query_information_thread_stub(
			HANDLE thread_handle,
			THREADINFOCLASS thread_information_class,
			PVOID thread_information,
			ULONG thread_information_length,
			PULONG return_length
		)
		{
			// The game uses NtQueryInformationThread with ThreadHideFromDebugger to check if a thread is hidden from the debugger
			if (thread_information_class == ThreadHideFromDebugger)
			{
				// Same thing here, the game provides an invalid length and expects STATUS_INFO_LENGTH_MISMATCH in return
				// Native behavior: length must be 1
				if (thread_information_length != 1)
				{
					return STATUS_INFO_LENGTH_MISMATCH;
				}

				// Check for alignment. If it's not 4-byte aligned, return STATUS_DATATYPE_MISALIGNMENT.
				if (reinterpret_cast<std::uintptr_t>(thread_information) % 4 != 0)
				{
					return 0x80000002L; // STATUS_DATATYPE_MISALIGNMENT
				}

				if (thread_information)
				{
					*static_cast<std::uint8_t*>(thread_information) = 1; // thread is hidden
				}

				if (return_length)
				{
					*return_length = 1;
				}

				return STATUS_SUCCESS;
			}

			return nt_query_information_thread_hook.invoke<NTSTATUS>(
				thread_handle,
				thread_information_class,
				thread_information,
				thread_information_length,
				return_length
			);
		}

		BOOL WINAPI check_remote_debugger_present_stub(HANDLE process, PBOOL debugger_present)
		{
			const auto result = check_remote_debugger_present_hook.invoke<BOOL>(process, debugger_present);

			if (debugger_present)
			{
				*debugger_present = FALSE;
			}

			return result;
		}

		struct ntdll_copy
		{
			void* address;
			size_t size;
			bool is_single_stepping;
		};
		std::recursive_mutex ntdll_copies_mutex;
		std::vector<ntdll_copy> ntdll_copies;
		
		struct SingleStepThread {
			DWORD thread_id;
			void* copy_address;
		};
		SingleStepThread single_stepping_threads[64]{};
		uint64_t g_ntdll_base = 0;
		using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
		NtProtectVirtualMemory_t g_direct_NtProtectVirtualMemory = nullptr;

		void hook_ntdll_copy(ntdll_copy copy)
		{
			const utils::nt::library ntdll("ntdll.dll");
			const auto nt_close = ntdll.get_proc<std::uintptr_t>("NtClose");
			const auto nt_query_system_information = ntdll.get_proc<std::uintptr_t>("NtQuerySystemInformation");
			const auto nt_query_information_process = ntdll.get_proc<std::uintptr_t>("NtQueryInformationProcess");
			const auto nt_set_information_thread = ntdll.get_proc<std::uintptr_t>("NtSetInformationThread");
			const auto nt_query_information_thread = ntdll.get_proc<std::uintptr_t>("NtQueryInformationThread");

			const auto ntdll_base = reinterpret_cast<std::uintptr_t>(ntdll.get_ptr());
			const auto copy_base = reinterpret_cast<std::uintptr_t>(copy.address);

			auto get_copy_address = [ntdll_base, copy_base](std::uintptr_t orig_fn) -> void*
			{
				if (!orig_fn) return nullptr;
				return reinterpret_cast<void*>(orig_fn - ntdll_base + copy_base);
			};

			if (auto* fn = get_copy_address(nt_close))
			{
				LOG("Arxan/AntiDebug", INFO, "Hooking NtClose in NTDLL copy at: {}", fn);
				utils::hook::jump(fn, nt_close_stub);
			}

			if (auto* fn = get_copy_address(nt_query_system_information))
			{
				LOG("Arxan/AntiDebug", INFO, "Hooking NtQuerySystemInformation in NTDLL copy at: {}", fn);
				utils::hook::jump(fn, nt_query_system_information_stub);
			}

			if (auto* fn = get_copy_address(nt_query_information_process))
			{
				LOG("Arxan/AntiDebug", INFO, "Hooking NtQueryInformationProcess in NTDLL copy at: {}", fn);
				utils::hook::jump(fn, nt_query_information_process_stub);
			}

			if (auto* fn = get_copy_address(nt_set_information_thread))
			{
				LOG("Arxan/AntiDebug", INFO, "Hooking NtSetInformationThread in NTDLL copy at: {}", fn);
				utils::hook::jump(fn, nt_set_information_thread_stub);
			}

			if (auto* fn = get_copy_address(nt_query_information_thread))
			{
				LOG("Arxan/AntiDebug", INFO, "Hooking NtQueryInformationThread in NTDLL copy at: {}", fn);
				utils::hook::jump(fn, nt_query_information_thread_stub);
			}
		}

		LONG WINAPI exception_filter(const LPEXCEPTION_POINTERS info)
		{
			const auto rec = info->ExceptionRecord;

			if (rec->ExceptionCode == 0x80000004 || rec->ExceptionCode == 0x40010006) // Single step
			{
				DWORD current_tid = GetCurrentThreadId();
				for (int i = 0; i < 64; ++i)
				{
					if (single_stepping_threads[i].thread_id == current_tid)
					{
						void* step_copy = single_stepping_threads[i].copy_address;
						single_stepping_threads[i].thread_id = 0;
						
						std::lock_guard<std::recursive_mutex> lock(ntdll_copies_mutex);
  						for (size_t j = 0; j < ntdll_copies.size(); ++j)
  						{
  							auto& copy = ntdll_copies[j];
  							if (copy.address == step_copy)
  							{
  								DWORD old_protect;
  								PVOID base = copy.address;
  								SIZE_T size = copy.size;
  								if (g_direct_NtProtectVirtualMemory) g_direct_NtProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_READWRITE, &old_protect);
  								copy.is_single_stepping = false;
  								break;
  							}
  						}
  						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}
			}
			if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->ExceptionInformation[0] == 8) // Execute fault
			{
				const auto fault_address = rec->ExceptionInformation[1];
				
				std::lock_guard<std::recursive_mutex> lock(ntdll_copies_mutex);
  				for (size_t j = 0; j < ntdll_copies.size(); ++j)
  				{
  					auto& copy = ntdll_copies[j];
					if (fault_address >= reinterpret_cast<uint64_t>(copy.address) && fault_address < reinterpret_cast<uint64_t>(copy.address) + copy.size)
					{
						if (copy.is_single_stepping)
						{
							// Arxan caught our single-step execute fault??
							return EXCEPTION_CONTINUE_EXECUTION;
						}
						
						// Restore execution protection so the copy can run natively
						DWORD old_protect;
						PVOID base = copy.address;
						SIZE_T size = copy.size;
						if (g_direct_NtProtectVirtualMemory) g_direct_NtProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_EXECUTE_READWRITE, &old_protect);
						
						info->ContextRecord->EFlags |= 0x100; // Trap Flag
						DWORD current_tid = GetCurrentThreadId();
						for (int i = 0; i < 64; ++i) {
							if (single_stepping_threads[i].thread_id == 0) {
								single_stepping_threads[i].thread_id = current_tid;
								single_stepping_threads[i].copy_address = copy.address;
								break;
							}
						}
						copy.is_single_stepping = true;
						
						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}
			}

			if (rec->ExceptionCode == STATUS_INVALID_HANDLE)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}

			return EXCEPTION_CONTINUE_SEARCH;
		}

		utils::hook::detour virtual_alloc_hook;

		LPVOID WINAPI virtual_alloc_stub(LPVOID address, SIZE_T size, DWORD allocation_type, DWORD protect)
		{
			if ((allocation_type & MEM_COMMIT) && protect == PAGE_EXECUTE_READWRITE && size > 0x100000 && size < 0x180000)
			{
				LOG("Arxan/AntiDebug", INFO, "[VirtualAlloc] Intercepted NTDLL copy allocation - size: {:X}", size);
				
				LPVOID allocated = virtual_alloc_hook.invoke<LPVOID>(address, size, allocation_type, PAGE_READWRITE);
				if (allocated)
				{
					std::lock_guard<std::recursive_mutex> lock(ntdll_copies_mutex);
					ntdll_copies.push_back({ allocated, size, false });
					LOG("Arxan/AntiDebug", INFO, "[VirtualAlloc] Registered NTDLL copy at: {}", allocated);
					
					// If this is the second copy, schedule unhook
					if (ntdll_copies.size() == 2) {
					    scheduler::once([]() {
					        virtual_alloc_hook.clear();
					        nt_close_hook.clear();
					        nt_query_information_process_hook.clear();
					        nt_query_system_information_hook.clear();
					        nt_set_information_thread_hook.clear();
					        nt_query_information_thread_hook.clear();
					        
					        // Clear VEH hooks in breakpoints.cpp
					        arxan::breakpoints::add_vectored_exception_handler_hook.clear();
					        arxan::breakpoints::remove_vectored_exception_handler_hook.clear();
					        
					        // Clear any exception filter hooks too
					        set_unhandled_exception_filter_hook.clear();
					        
					        // 2. Clean up our trampoline protection
					        // 2. Clean up our trampoline protection
					        if (g_direct_NtProtectVirtualMemory) {
					            DWORD old_protect;
					            PVOID base = reinterpret_cast<PVOID>(g_direct_NtProtectVirtualMemory);
					            SIZE_T t_size = 0x1000;
					            VirtualProtect(base, t_size, PAGE_READWRITE, &old_protect);
					        }
					        
					        // 3. Restore all NTDLL copies to PAGE_EXECUTE_READWRITE so they run natively without triggering VEH
					        {
					            std::lock_guard<std::recursive_mutex> inner_lock(ntdll_copies_mutex);
					            for (auto& copy : ntdll_copies) {
					                DWORD old_protect;
					                VirtualProtect(copy.address, copy.size, PAGE_EXECUTE_READWRITE, &old_protect);
					            }
					        }
					        
					        // 4. Remove our VEH handler so Arxan doesn't flag it
					        if (g_veh_handle) {
					            RemoveVectoredExceptionHandler(g_veh_handle);
					            g_veh_handle = nullptr;
					        }
					        
					        LOG("Arxan/AntiDebug", INFO, "[VirtualAlloc] SUPER STEALTH UNHOOK: Disabled specific hooks, restored copies, removed VEH!");
					    }, scheduler::pipeline::async, std::chrono::milliseconds(5000));
					}
				}
				return allocated;
			}

			return virtual_alloc_hook.invoke<LPVOID>(address, size, allocation_type, protect);
		}

		BOOL CALLBACK enum_windows_callback_nullsub(HWND hwnd, LPARAM)
		{
			return TRUE;
		}

		BOOL WINAPI enum_windows_stub(WNDENUMPROC callback, LPARAM lparam)
		{
			const auto ret = _ReturnAddress();

			const auto game = utils::nt::library{};
			const auto source_module = utils::nt::library::get_by_address(ret);

			if (source_module == game)
			{
				// The game uses EnumWindows to iterate over all top-level windows
				// and inspect their titles for blacklisted/debugging-related strings.
				//
				// Instead of letting it enumerate every window and call several WinAPI
				// functions per window, pass a callback that does nothing. This keeps
				// the EnumWindows call itself successful while preventing the original
				// callback logic from running.
				//
				// So far it does not appear to validate whether the original callback
				// was called or whether any windows were actually processed.
				return enum_windows_hook.invoke<BOOL>(enum_windows_callback_nullsub, lparam);
			}

			return enum_windows_hook.invoke<BOOL>(callback, lparam);
		}
	}

	struct component final : generic_component
	{
	public:
		void post_load() override
		{
			g_ntdll_base = reinterpret_cast<uint64_t>(utils::nt::library("ntdll.dll").get_ptr());
			
			// Initialize global pointer for VEH with a direct syscall stub
			uint8_t syscall_stub[] = {
				0x4C, 0x8B, 0xD1,             // mov r10, rcx
				0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 50h
				0x0F, 0x05,                   // syscall
				0xC3                          // ret
			};
			void* tramp_ntprotect = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (tramp_ntprotect) {
				memcpy(tramp_ntprotect, syscall_stub, sizeof(syscall_stub));
				g_direct_NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(tramp_ntprotect);
			}

			auto* dll_characteristics = &utils::nt::library().get_optional_header()->DllCharacteristics;
			utils::hook::set<WORD>(dll_characteristics, *dll_characteristics | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

			// Bypass TLS callback based anti-debug
			// disable_tls_callbacks();

			// Bypass standard debugging checks
			restore_debug_functions();

			hide_being_debugged();
			scheduler::loop(hide_being_debugged, scheduler::pipeline::async);

			g_veh_handle = AddVectoredExceptionHandler(1, exception_filter);

			// create_mutex_ex_a_hook.create(CreateMutexExA, create_mutex_ex_a_stub);
			// create_thread_hook.create(CreateThread, create_thread_stub);
			// enum_windows_hook.create(EnumWindows, enum_windows_stub);

			const utils::nt::library ntdll("ntdll.dll");
			nt_close_hook.create(ntdll.get_proc<void*>("NtClose"), nt_close_stub);

			const auto nt_query_information_process = ntdll.get_proc<void*>("NtQueryInformationProcess");
			nt_query_information_process_hook.create(nt_query_information_process, nt_query_information_process_stub);

			const auto nt_query_system_information = ntdll.get_proc<void*>("NtQuerySystemInformation");
			nt_query_system_information_hook.create(nt_query_system_information, nt_query_system_information_stub);
			nt_query_system_information_hook.move();

			// open_process_hook.create(OpenProcess, open_process_stub);

#ifndef NDEBUG
			auto* get_thread_context_func = utils::nt::library("kernelbase.dll").get_proc<void*>("GetThreadContext");
			// get_thread_context_hook.create(get_thread_context_func, get_thread_context_stub);
#endif

			// utils::hook::copy(this->window_text_buffer_, GetWindowTextA, sizeof(this->window_text_buffer_));
			// utils::hook::jump(GetWindowTextA, get_window_text_a_stub, true, true);
			// utils::hook::move_hook(GetWindowTextA);

			auto* sys_met_import = utils::nt::library{}.get_iat_entry("user32.dll", "GetSystemMetrics");
			// if (sys_met_import) utils::hook::set(sys_met_import, get_system_metrics_stub);

			const auto nt_set_information_thread = ntdll.get_proc<void*>("NtSetInformationThread");
			nt_set_information_thread_hook.create(nt_set_information_thread, nt_set_information_thread_stub);
			nt_set_information_thread_hook.move();

			const auto nt_query_information_thread = ntdll.get_proc<void*>("NtQueryInformationThread");
			nt_query_information_thread_hook.create(nt_query_information_thread, nt_query_information_thread_stub);
			nt_query_information_thread_hook.move();

			auto* virtual_alloc_func = utils::nt::library("kernel32.dll").get_proc<void*>("VirtualAlloc");
			virtual_alloc_hook.create(virtual_alloc_func, virtual_alloc_stub);

			

			auto* check_remote_debugger_present_func = utils::nt::library("kernel32.dll").get_proc<void*>("CheckRemoteDebuggerPresent");
			// check_remote_debugger_present_hook.create(check_remote_debugger_present_func, check_remote_debugger_present_stub);
		}

		// post_thread_setup removed, NTDLL copies are now hooked via VEH on execute faults

		component_priority priority() const override
		{
			return component_priority::arxan;
		}

	private:
		uint8_t window_text_buffer_[15]{};
	};
}

// REGISTER_COMPONENT(arxan::anti_debug::component)
