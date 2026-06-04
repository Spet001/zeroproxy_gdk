#include <iostream>
#include <Windows.h>

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* ptr = GetProcAddress(ntdll, "NtProtectVirtualMemory");
    unsigned char* bytes = (unsigned char*)ptr;
    for(int i=0; i<10; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
    return 0;
}
