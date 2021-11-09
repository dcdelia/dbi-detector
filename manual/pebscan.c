#include <windows.h>
#include <ntdef.h>
#include <stdio.h>

#define PTR_ADD_OFFSET(Pointer, Offset)   ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

#define LDR_DATA_TABLE_ENTRY_SIZE_WIN7_32   FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, BaseNameHashValue)

#define ProcessBasicInformation 0
#define ProcessWow64Information 26

typedef DWORD PROCESSINFOCLASS; // lol


#if 0
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks; /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
    LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
    PVOID DllBase; /* 0x18 */
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName; /* 0x24 */
    UNICODE_STRING BaseDllName; /* 0x28 */
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
         LIST_ENTRY HashLinks;
         struct
         {
              PVOID SectionPointer;
              ULONG CheckSum;
         };
    };
    union
    {
         ULONG TimeDateStamp;
         PVOID LoadedImports;
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#else
typedef BOOLEAN (NTAPI *PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
    );

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef PVOID PLDR_DDAG_NODE; // TODO

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT *LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY32;
#endif


typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    BOOLEAN                 Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
	PPEB_LDR_DATA		Ldr;
} PEB, *PPEB;

typedef NTSTATUS (NTAPI * _NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS (NTAPI *_NtReadVirtualMemory)(
  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress,
  OUT PVOID               Buffer,
  IN ULONG                NumberOfBytesToRead,
  OUT PULONG              NumberOfBytesReaded OPTIONAL );

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

_NtQueryInformationProcess NtQueryInformationProcess;
_NtReadVirtualMemory NtReadVirtualMemory;

int main() {
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetLibraryProcAddress("ntdll.dll", "NtQueryInformationProcess");
    NtReadVirtualMemory = (_NtReadVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtReadVirtualMemory");

    PROCESS_BASIC_INFORMATION basicInfo;
    HANDLE curProcess = GetCurrentProcess();
    NtQueryInformationProcess(
        curProcess,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
        );
    
    PPEB pPEBfs;
    __asm__ volatile(
        ".intel_syntax noprefix ;"
        "mov %0, dword ptr fs:[0x30] ;"
        ".att_syntax noprefix ;"
        : "+r"(pPEBfs) : :
    );

    PVOID peb;
    NtReadVirtualMemory(curProcess, &basicInfo.PebBaseAddress, &peb, sizeof(PVOID), NULL);
    
    printf("PEB from fs[0x30]:\t%p\n", pPEBfs);
    printf("PEB from NTQueryIp-0:\t%p\n", basicInfo.PebBaseAddress);
    printf("PEB from NT combo:\t%p\n", peb);

    PPEB ppebwow64;
    NTSTATUS status = NtQueryInformationProcess(
        curProcess,
        ProcessWow64Information,
        &ppebwow64,
        sizeof(ULONG_PTR),
        NULL
        );

    if (NT_SUCCESS(status))
    {
        printf("PEB from NTQueryIp-23:\t%p\n", ppebwow64);
    } else {
        printf("PEB from NTQueryIp-23:\t RICC\n");
    }

    PPEB_LDR_DATA ldr;

    NtReadVirtualMemory(curProcess,
        PTR_ADD_OFFSET(peb, FIELD_OFFSET(PEB, Ldr)),
        &ldr,
        sizeof(PVOID),
        NULL);

    printf("pebLdr: %p %p\n", ldr, pPEBfs->Ldr);
    
    PEB_LDR_DATA pebLdrData;

    NtReadVirtualMemory(curProcess,
        ldr,
        &pebLdrData,
        sizeof(PEB_LDR_DATA),
        NULL);

    PLIST_ENTRY startLink, currentLink;
    //int i = 0;
    startLink = PTR_ADD_OFFSET(ldr, FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    currentLink = pebLdrData.InLoadOrderModuleList.Flink;

    LDR_DATA_TABLE_ENTRY currentEntry;

    ULONG dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN7_32;

    while (currentLink != startLink) {
        PVOID addressOfEntry;
        NTSTATUS status;
        addressOfEntry = CONTAINING_RECORD(currentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        printf("KTM\n");
        status = NtReadVirtualMemory(
            curProcess,
            addressOfEntry,
            &currentEntry,
            dataTableEntrySize,
            NULL
            );

        if (!NT_SUCCESS(status)) break;

        currentLink = currentEntry.InLoadOrderLinks.Flink;
    }

    return 0;
}