#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <psapi.h>

#include "seh.h"

#ifndef PAGE_TARGETS_INVALID
#define PAGE_TARGETS_INVALID	0x40000000
#endif
#ifndef PAGE_TARGETS_NO_UPDATE
#define PAGE_TARGETS_NO_UPDATE	0x40000000
#endif

const char* memMaskToStr(DWORD protect, int* guard) {
    // discards flags that are not relevant...
    DWORD clearMask = ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE | PAGE_TARGETS_INVALID | PAGE_TARGETS_NO_UPDATE);
    *guard = protect & PAGE_GUARD ? 1 : 0;

    // TODO is PAGE_EXECUTE_WRITECOPY
    const char* str;
	switch (protect & clearMask) {
	case PAGE_EXECUTE:
		str = "--X"; break;
	case PAGE_EXECUTE_READ:
		str = "R-X"; break;
	case PAGE_EXECUTE_READWRITE:
        str = "RWX"; break;
	case PAGE_EXECUTE_WRITECOPY:
        str = "WXcopy"; break;
	case PAGE_READONLY:
		str = "R--"; break;
	case PAGE_READWRITE:
        str = "RW-"; break;
	case PAGE_WRITECOPY:
		str = "RWcopy"; break;
    case PAGE_NOACCESS:
        str = "noaccess"; break;
	default:
		str = "UNKNOWN"; // should not happen
	}

    return str;
}

void lookupName(PVOID addr, char* path, size_t size) {
    if (GetModuleFileNameA((HINSTANCE)addr, path, size)) {
        return;
    }

    if (GetMappedFileNameA(GetCurrentProcess(), addr, path, size)) {
        return;
    }

    sprintf(path, "unsolved");
}

void queryMemoryRegions() {
    MEMORY_BASIC_INFORMATION mem;
	SIZE_T numBytes;
	uintptr_t address = 0;
	//PVOID maxAddr = 0;

	while (1) {
		numBytes = VirtualQuery((LPCVOID)address, &mem, sizeof(mem));
        if (!numBytes) {
            //printf("Invalid query to VirtualQuery!\n");
            break;
        }

		// workaround for not getting stuck on the last valid block (see above)
		//if ((maxAddr && maxAddr >= mem.BaseAddress) || end <= (ADDRINT)mem.BaseAddress) break;
		//maxAddr = mem.BaseAddress;

		uintptr_t startAddr = (uintptr_t)mem.BaseAddress;
		SIZE_T size = mem.RegionSize;

        int guard = 0;
        const char *mask = NULL, *state = NULL;
        switch (mem.State) {
            case MEM_COMMIT:
                state = "commit";
                mask = memMaskToStr(mem.Protect, &guard);
                break;
            case MEM_FREE:
                state = "free";
                break;
            case MEM_RESERVE:
                state = "reserved";
                break;
        }

        const char* type = NULL;
        if (mem.State != MEM_FREE) {
            switch (mem.Type) {
                case MEM_IMAGE:
                    type = "image";
                    break;
                case MEM_MAPPED:
                    type = "mapped";
                    break;
                case MEM_PRIVATE:
                    type = "private";
                    break;
            }
        }

        // TODO sprintf
        address += size;
        printf("[%x, %x]", startAddr, address-1);
        if (mask) {
            printf(" %s", mask);
            if (guard) printf(" GUARD");
        } else {
            printf(" %s", state);
        }
        if (type) {
            printf(" %s", type);
            // let's try to look up file name
            char path[MAX_PATH];
            lookupName(mem.AllocationBase, path, sizeof(path));
            printf(" %s", path);
        }
        printf("\n");

        #if 0
        if (mask) {
            printf("[%x, %x] %s%s %s\n", startAddr, address-1, mask, guard ? " GUARD" : "", type);
        } else {
            printf("[%x, %x] %s\n", startAddr, address-1, state);
        }
        #endif
		
	}
}

void lookForLibrary(uintptr_t addr) {
    unsigned short MZ = NULL;
    __seh_try {
        MZ = *((unsigned short*)addr);
        if (MZ == 0x5a4d) {
            printf("Found MZ at %x\n", addr);
        }
    }
    __seh_except(info, context)
    {
        //if(info->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        //    fputs("Access violation exception raised.\n", stdout);
    }
    __seh_end
    // The previous __seh_end call is necessary, so don't forget it.
}

// 32-bit only
// ROPScozzo says: A DLL can be loaded at 10240 different positions in the
// range of addresses 0x50000000 - 0x78000000 with the same alignment (64KB)
void sczASLR() {
    uintptr_t start = 0x50000000;
    uintptr_t end = 0x78000000;

    while (start <= end) {
        char path[MAX_PATH];
        if (GetModuleFileNameA((HINSTANCE)start, path, sizeof(path))) {
            printf("Found DLL at %x: %s\n", start, path);
        } else lookForLibrary(start);
        if (start == 0x78000000) printf("MUORI\n");
        start += 64*1024;
    }

    uintptr_t end_wow64 = 0x7e000000;
    while (start <= end_wow64) {
        char path[MAX_PATH];
        if (GetModuleFileNameA((HINSTANCE)start, path, sizeof(path))) {
            printf("Found WoW64 DLL at %x: %s\n", start, path);
        }
        start += 64*1024;
    }
}

int main() {

    printf("DBI Evader v1.0\n");

    queryMemoryRegions();

    printf("\nEnter SCZ.... PPUH!\n");

#if 0
    char* drio = (char*)0x71000000;
    char buf[9];
    memcpy(buf, drio, 8);
    buf[8] = 0;
    printf("KTM: %s\n", buf);
#endif
    sczASLR();

    printf("Sleeping now...\n");

    fflush(0); // for cygwin terminal
    Sleep(INFINITE);
    
    return 0;
}