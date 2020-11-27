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

// code
/*PPH_STRING PhCreateStringEx(
    _In_opt_ PWCHAR Buffer,
    _In_ SIZE_T Length
    )
{
    PPH_STRING string;

    string = PhCreateObject(
        UFIELD_OFFSET(PH_STRING, Data) + Length + sizeof(UNICODE_NULL), // Null terminator for compatibility
        PhStringType
        );

    assert(!(Length & 1));
    string->Length = Length;
    string->Buffer = string->Data;
    *(PWCHAR)PTR_ADD_OFFSET(string->Buffer, Length) = UNICODE_NULL;

    if (Buffer)
    {
        memcpy(string->Buffer, Buffer, Length);
    }

    return string;
}


PPH_STRING
PhCreateStringFromUnicodeString(
    _In_ PUNICODE_STRING UnicodeString
    )
{
    if (UnicodeString->Length == 0)
        return PhReferenceEmptyString();

    return PhCreateStringEx(UnicodeString->Buffer, UnicodeString->Length);
}*/

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

            // Check if we have a duplicate base address.
            /*if (PhFindEntryHashtable(BaseAddressHashtable, &allocationBase))
            {
                continue;
            }*/

            if (!NT_SUCCESS(PhGetProcessMappedFileName(
                ProcessHandle,
                allocationBase,
                &fileName
                )))
            {
                continue;
            }

            //PhAddEntryHashtable(BaseAddressHashtable, &allocationBase);

            /*cont = PhpCallbackMappedFileOrImage(
                allocationBase,
                allocationSize,
                type,
                fileName,
                Callback,
                Context,
                BaseAddressHashtable
                );

            if (!cont)
                break;*/

            // scozzerprinter
            //printf("<Scozzerprinter>\n");
            wprintf(L"Filename: %s\n", fileName);
            char* type_s = (basicInfo.Type == MEM_MAPPED) ? "mapped" : "image";
            printf("Base, size, type: %p %x %s\n", allocationBase, allocationSize, type_s);
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