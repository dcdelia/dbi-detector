#include <windows.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>

#define PTR_ADD_OFFSET(Pointer, Offset)   ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

#define PH_MODULE_TYPE_MAPPED_FILE 2
#define PH_MODULE_TYPE_MAPPED_IMAGE 5

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI* _NtQueryVirtualMemory)(
  HANDLE                   ProcessHandle,
  PVOID                    BaseAddress,
  MEMORY_INFORMATION_CLASS MemoryInformationClass,
  PVOID                    MemoryInformation,
  SIZE_T                   MemoryInformationLength,
  PSIZE_T                  ReturnLength
);

// dynamically imported functions
_NtQueryVirtualMemory NtQueryVirtualMemory;

// prototype for test
void doCheck(PBYTE baseAddress);

NTSTATUS PhGetProcessMappedFileName(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ wchar_t *FileName
    )
{
    NTSTATUS status;
    SIZE_T bufferSize;
    SIZE_T returnLength;
    PUNICODE_STRING buffer;

    returnLength = 0;
    bufferSize = 0x100;
    buffer = malloc(bufferSize);

    status = NtQueryVirtualMemory(
        ProcessHandle,
        BaseAddress,
        MemoryMappedFilenameInformation,
        buffer,
        bufferSize,
        &returnLength
        );

    if (status == STATUS_BUFFER_OVERFLOW && returnLength > 0) // returnLength > 0 required for MemoryMappedFilename on Windows 7 SP1 (dmex)
    {
        free(buffer);
        bufferSize = returnLength;
        buffer = malloc(bufferSize);

        status = NtQueryVirtualMemory(
            ProcessHandle,
            BaseAddress,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &returnLength
            );
    }

    if (!NT_SUCCESS(status))
    {
        free(buffer);
        return status;
    }

    swprintf(FileName, 64, L"%s", buffer->Buffer);
    free(buffer);

    return status;
}


VOID PhpEnumGenericMappedFilesAndImages(HANDLE ProcessHandle) {
    BOOLEAN querySucceeded;
    PVOID baseAddress;
    MEMORY_BASIC_INFORMATION basicInfo;

    baseAddress = (PVOID)0;

    if (!NT_SUCCESS(NtQueryVirtualMemory(
        ProcessHandle,
        baseAddress,
        MemoryBasicInformation,
        &basicInfo,
        sizeof(MEMORY_BASIC_INFORMATION),
        NULL
        )))
    {
        return;
    }

    querySucceeded = TRUE;

    while (querySucceeded)
    {
        PVOID allocationBase;
        SIZE_T allocationSize;
        ULONG type;
        wchar_t fileName[64];
        BOOLEAN cont;

        if (basicInfo.Type == MEM_MAPPED || basicInfo.Type == MEM_IMAGE)
        {
            if (basicInfo.Type == MEM_MAPPED)
                type = PH_MODULE_TYPE_MAPPED_FILE;
            else
                type = PH_MODULE_TYPE_MAPPED_IMAGE;

            // Find the total allocation size.

            allocationBase = basicInfo.AllocationBase;
            allocationSize = 0;

            do
            {
                baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
                allocationSize += basicInfo.RegionSize;

                if (!NT_SUCCESS(NtQueryVirtualMemory(
                    ProcessHandle,
                    baseAddress,
                    MemoryBasicInformation,
                    &basicInfo,
                    sizeof(MEMORY_BASIC_INFORMATION),
                    NULL
                    )))
                {
                    querySucceeded = FALSE;
                    break;
                }
            } while (basicInfo.AllocationBase == allocationBase);


            if (!NT_SUCCESS(PhGetProcessMappedFileName(
                ProcessHandle,
                allocationBase,
                &fileName
                )))
            {
                continue;
            }

            wprintf(L"Filename: %s\n", fileName);
            char* type_s = (basicInfo.Type == MEM_MAPPED) ? "mapped" : "image";
            printf("Base, size, type: %p %x %s\n", allocationBase, allocationSize, type_s);

            // DO TEST
            if (!wcsstr(fileName, L"Windows")) {
                printf("trying detection...\n");
                fflush(0);
                doCheck((PBYTE)allocationBase);
            }
        }
        else
        {
            baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);

            if (!NT_SUCCESS(NtQueryVirtualMemory(
                ProcessHandle,
                baseAddress,
                MemoryBasicInformation,
                &basicInfo,
                sizeof(MEMORY_BASIC_INFORMATION),
                NULL
                )))
            {
                querySucceeded = FALSE;
            }
        }
    }
}


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

int main() {
    NtQueryVirtualMemory = GetLibraryProcAddress("ntdll.dll", "NtQueryVirtualMemory");

    HANDLE curProc = GetCurrentProcess();
    PhpEnumGenericMappedFilesAndImages(curProc);
    return 0;
}

// Tail stuff :)

int isEqual(char* str1, char* str2)
{
	int i;

	for(i=0; i < 8; i++)
	{
		if(str1[i] != str2[i])
			return 0;
	}

	return 1;
}

void lowercase(char string[])
{
   int  i = 0;

   while ( i < 8 )
   {
      string[i] = tolower(string[i]);
      i++;
   }
}

void doCheck(PBYTE baseAddress) {
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS32 nthdr;
	PIMAGE_SECTION_HEADER sectionhdr;
	DWORD nro_sections, MyPtr, cbNeeded, processID;
	DWORD* argvptr;

    doshdr = (PIMAGE_DOS_HEADER)baseAddress;
    //printf("DOS_HEADER: %p\n", doshdr);

    nthdr = (PIMAGE_NT_HEADERS32)((char *)(doshdr->e_lfanew + (LONG)baseAddress));
    //printf("NT_HEADER: %p\n", nthdr);

    nro_sections = nthdr->FileHeader.NumberOfSections;
    //printf("[+] Number of Sections: %d\n", nro_sections);

    sectionhdr = (PIMAGE_SECTION_HEADER)((char *)nthdr + sizeof(IMAGE_NT_HEADERS32));
    //printf("SECTION_HEADER: %p\n", sectionhdr);

    for (int j = 0; j < nro_sections; j++)
    {
        char AuxName[8];
        memcpy(AuxName, sectionhdr->Name, 8);
		lowercase(AuxName);

		if((isEqual(AuxName, ".charmveC")) || (isEqual(AuxName, ".pinclie")))
		{
			//system("pause");
			printf("Detected\n");
		}
		sectionhdr = (PIMAGE_SECTION_HEADER)((char*)sectionhdr + sizeof(IMAGE_SECTION_HEADER));
    }
}