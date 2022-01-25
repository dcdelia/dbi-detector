#include "../inc/heavensgate.h"


#ifdef __i386__

bool ctx_32to64(){
    u32 cs_32=0;

    asm volatile(
        "movl %%cs, %0;"
        : "=r" (cs_32)
    );
    
    //printf("CS = 0x%02x\n", cs_32);

    u64 cs_64 = 0;
    __block_32(&cs_64);
    //printf("CS = 0x%02llx\n", cs_64);
    
    if (cs_64 != 0x33) return True;

    return False;
}

#else

bool ctx_64to32(){

    // do getsid(0) ia-32 syscall
    asm volatile(
        "mov %0, %%eax;"
        "mov %1, %%ebx;"
        "int $0x80;"
        : /* no output */
        : "g"(SYSCNO_GETSID), "g"(0)
    );   
    // If the func returns, no Pin
    return False;
}
#endif
