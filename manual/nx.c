#include <windows.h>
#include <stdio.h>

typedef void (*_foo)( );

int main() {
    _foo foo;
    PBYTE ktm = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    *ktm = 0xC3;
    foo = (_foo)ktm;

    printf("Here...\n");
    //VirtualProtect(ktm, 4096, PAGE_EXECUTE_READWRITE, NULL);
    foo();
    printf("There!\n");

    return 0;
}