#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <psapi.h>

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
		str = "--x"; break;
	case PAGE_EXECUTE_READ:
		str = "r-x"; break;
	case PAGE_EXECUTE_READWRITE:
        str = "rwx"; break;
	case PAGE_EXECUTE_WRITECOPY:
        str = "wxcopy"; break;
	case PAGE_READONLY:
		str = "r--"; break;
	case PAGE_READWRITE:
        str = "rw-"; break;
	case PAGE_WRITECOPY:
		str = "rwcopy"; break;
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

int main() {

    printf("DBI Evader v1.0\n");

    queryMemoryRegions();

    printf("\nEnter SCZ.... PPUH!\n");

    fflush(0);
    Sleep(INFINITE);
    
    return 0;
}