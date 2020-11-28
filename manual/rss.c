#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define STR_(X) #X
#define STR(X) STR_(X) // expand before conversion
#define PRINT_FIELD(x,d)    do { printf(STR(x)": %d\n", d->x); } while (0)


void printInfo(PPROCESS_MEMORY_COUNTERS data) {
    PRINT_FIELD(cb, data);
    PRINT_FIELD(PageFaultCount, data);
    PRINT_FIELD(PeakWorkingSetSize, data);
    PRINT_FIELD(WorkingSetSize, data);
    PRINT_FIELD(QuotaPeakPagedPoolUsage, data);
    PRINT_FIELD(QuotaPagedPoolUsage, data);
    PRINT_FIELD(QuotaPeakNonPagedPoolUsage, data);
    PRINT_FIELD(QuotaNonPagedPoolUsage, data);
    PRINT_FIELD(PagefileUsage, data);
    PRINT_FIELD(PeakPagefileUsage, data);
}

int main() {
    HANDLE proc = GetCurrentProcess();
    PROCESS_MEMORY_COUNTERS memCounter;
    GetProcessMemoryInfo(proc, &memCounter, sizeof(memCounter));
    printInfo(&memCounter);
    return 0;
}