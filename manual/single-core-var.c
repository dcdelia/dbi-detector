#include <stdio.h>
#include <windows.h>

#define LOOP_COUNT  20000
#define TRIALS      30

typedef struct {
    volatile uintptr_t* self;
    volatile uintptr_t* other;
} scz_t;

unsigned checkSingleCoreWorker(scz_t* scz) {
    unsigned count = 0; uintptr_t last = 0;
    for (unsigned i = 0; i < LOOP_COUNT; ++i) {
        unsigned cur = *(scz->other);
        if (cur == last) count++; else last = cur;
        __asm__ volatile ( // busy loop
            "xorl %%eax, %%eax ;"
            "movl $10000, %%eax ;"
            "1: decl %%eax ;"
            "jnz 1b;"
            : : : "eax" );
        (*(scz->self))++;
    }
    return count;
}

DWORD WINAPI checkSingleCoreThread(void *arg) {
    DWORD count = checkSingleCoreWorker((scz_t*)arg);
    return count;
}

int doTest() {
    volatile uintptr_t cntMain, cntOther;
    scz_t mainT = { &cntMain, &cntOther };
    scz_t otherT = { &cntOther, &cntMain };
    HANDLE otherThread = CreateThread(NULL, 0,
                        checkSingleCoreThread,
                        (LPVOID)&otherT,
                        0, 0);
    DWORD countMain = checkSingleCoreWorker(&mainT);
    WaitForSingleObject(otherThread, INFINITE);
    DWORD countOther;
    GetExitCodeThread(otherThread, &countOther);
    //printf("Counters: main %d other %d\n", countMain, countOther);
    return (countMain+countOther) >= LOOP_COUNT/2;
}

DWORD_PTR forceSingleCore(DWORD_PTR *origAffinity) {
    HANDLE hProcess = GetCurrentProcess();
    DWORD_PTR customAffinity, systemAffinity;
    BOOL ret = GetProcessAffinityMask(hProcess, origAffinity, &systemAffinity);
    if (!ret) { printf("Cannot read process affinity!\n"); return 0; }
    customAffinity = *origAffinity;
    printf("affinity> process: %llx - system: %llx\n", *origAffinity, systemAffinity);

    for (unsigned i = 0; i < sizeof(DWORD_PTR)*8; ++i) {
        // start with i-th bit, try each single core till success
        char b = (*origAffinity >> i) & 0xFF;
        if (!b) continue;
        customAffinity = 1 << i;
        ret = SetProcessAffinityMask(hProcess, customAffinity);
        if (ret) {
            printf("single-core> enforcing %llx as affinity mask...\n", customAffinity);
            return customAffinity;
        }
    }

    printf("Cannot set process affinity!\n");
    return 0;
}

int main(int argc, char* argv[]) {
    int ret;
    int success = 0, fail = 0, trials = TRIALS;
    if (argc > 1) trials = atoi(argv[1]);
    while (trials--) {
        ret = doTest();
        if (ret) ++fail; else ++success;
    }
    printf("Output: OK %d KO %d\n", success, fail);
    // now I will enforce single-core by process affinity
    DWORD_PTR origAffinity, currAffinity;
    currAffinity = forceSingleCore(&origAffinity);
    Sleep(100); // make it happen
    ret = doTest();
    printf("Output: %d\n", ret);
    return 0;
}