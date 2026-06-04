#include <windows.h>
#include <iostream>

void* create_pure_syscall_stub(void* orig_func) {
    uint8_t* ptr = (uint8_t*)orig_func;
    uint32_t syscall_num = 0;
    
    // Scan up to 32 bytes to find 'mov eax, <syscall_num>' which is B8 XX XX XX XX
    for (int i = 0; i < 32; ++i) {
        if (ptr[i] == 0xB8) {
            syscall_num = *(uint32_t*)(&ptr[i + 1]);
            break;
        }
    }
    
    if (syscall_num == 0) {
        printf("Failed to find syscall number!\n");
        return nullptr;
    }
    
    printf("Syscall number: %X\n", syscall_num);
    
    void* tramp = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return nullptr;
    
    uint8_t stub[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_num
        0x0F, 0x05,                   // syscall
        0xC3                          // ret
    };
    
    *(uint32_t*)(&stub[4]) = syscall_num;
    memcpy(tramp, stub, sizeof(stub));
    
    return tramp;
}

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* orig = GetProcAddress(ntdll, "NtProtectVirtualMemory");
    void* tramp = create_pure_syscall_stub(orig);
    printf("Trampoline at %p\n", tramp);
    return 0;
}
