//smc.c
#include <stdio.h>
#include <windows.h>

void foo() {
    int var = -1;

    asm ("call bar\n\t"
         "bar: pop %%eax\n\t"
         "movl $0xcafebabe, 9(%%eax)\n\t"
         // this is an attempt to replace 0xffffffff                                                                                                                                   
         // with 0xcafebabe in the next instruction                                                                                                                                    
         "movl $0xffffffff,%%eax\n\t"
         : "=rax"(var));
    printf("addr - 0x%x\n", var);
}
int main() {
    DWORD old, new;
    MEMORY_BASIC_INFORMATION minfo;

    VirtualQuery((void *)0x401570, &minfo, 30);
    new = minfo.Protect;
    new = PAGE_EXECUTE_READWRITE;
    if (VirtualProtect((void*)0x401570, 30, new, &old) == 0) {
        printf("VirtualProtect() failed\n");
        fflush(stdout);
    }

    foo();
}