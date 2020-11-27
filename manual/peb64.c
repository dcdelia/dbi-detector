#include <windows.h>
#include <stdio.h>
#include <ntdef.h>
#include <winternl.h>

typedef struct _PEB32 {
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE padding2[53];
	PVOID ApiSetMap; // 0x38
	BYTE padding3[16];
	PVOID ReadOnlySharedMemoryBase; // 0x4c
	BYTE padding4[8];
	PVOID AnsiCodePageData; // 0x58
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag; // 0x68
	BYTE padding5[36];
	PVOID ProcessHeaps; // 0x90
	PVOID GdiSharedHandleTable; // 0x94
	BYTE padding6[336];
	PVOID pShimData;
	BYTE padding7[12];
	PVOID ActivationContextData;
	BYTE padding8[4];
	PVOID SystemDefaultActivationContextData;
	BYTE padding9[52];
	PVOID pContextData;
	BYTE padding10[4];
	BYTE padding11[4]; // DCD added to account for TracingFlags on Win7
} PEB32, *PPEB32;

// credits: Rolf Rolles http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html
typedef struct _PEB64 {
	BYTE padding1[2]; // pad 0x1
	BYTE BeingDebugged; // @0x02 byte
	BYTE padding2[0x68 - 3]; // pad 0x65
	BYTE ptr_ApiSetMap[8]; // @0x68
	BYTE padding3[0x88 - 0x70]; // pad 0x18
	BYTE ptr_ReadOnlySharedMemoryBase[8]; // @0x88
	BYTE padding4[0xA0 - 0x90]; // pad 0x10
	BYTE ptr_AnsiCodePageData[8]; // @0xA0
	BYTE padding5a[0xB8 - 0xA8]; // pad 0x10
	BYTE NumberOfProcessors[4]; // @OxB8 dword
	BYTE NtGlobalFlag[4]; // @OxBC dword
	BYTE padding5[0x2D8 - 0xC0]; // pad 0x218
									// DCD: ProcessHeaps and GdiSharedHandleTable are unused
	BYTE ptr_pShimData[8]; // @0x2D8
	BYTE padding7[0x2F8 - 0x2E0]; // pad 0x18
	BYTE ptr_ActivationContextData[8]; // @0x2F8
	BYTE padding8[0x308 - 0x300]; // pad 0x8
	BYTE ptr_SystemDefaultActivationContextData[8]; // @0x308
	BYTE padding9[0x368 - 0x310]; // pad 0x58
	BYTE ptr_pContextData[8]; // @0x368
	BYTE padding10[4 + 0x37C - 0x370]; // pImageHeaderHash + TracingFlags + 4-byte padding for alignment
} PEB64, *PPEB64;

//typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64
{
    NTSTATUS ExitStatus;
    ULONG64  PebBaseAddress;
    ULONG64  AffinityMask;
    KPRIORITY BasePriority;
    ULONG64  UniqueProcessId;
    ULONG64  InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION_WOW64, *PPROCESS_BASIC_INFORMATION_WOW64;

NTSTATUS (NTAPI *NtWow64QueryInformationProcess64) (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) = NULL;

int main() {
#if 0
    PEB32* peb32 = NULL;
	PEB64* peb64 = NULL;
	
    // TODO add WoW64 check
	BYTE* teb32 = (BYTE*)__readfsdword(0x18); // = (BYTE*)NtCurrentTeb();
    BYTE* teb64 = teb32 - 0x2000;
	peb32 = (PEB32*)(*(DWORD*)(teb32 + 0x30));
	peb64 = (PEB64*)(*(DWORD64*)(teb64 + 0x60)); // TODO mmmm

    ULONG ktm64 = *((ULONG*)&peb64->NtGlobalFlag);
    printf("PEB32: %d %u\n", (int)peb32->BeingDebugged, peb32->NtGlobalFlag);
    printf("PEB64: %d %u\n", (int)peb64->BeingDebugged, ktm64);
#else
    PBYTE peb32, peb64;
    PBYTE teb32, teb64; // TODO double check with Hasherazade for PEB64

    teb32 = (PBYTE)__readfsdword(0x18); // = (BYTE*)NtCurrentTeb();
    teb64 = teb32 - 0x2000;
	peb32 = (PBYTE)(*(DWORD*)(teb32 + 0x30));
	peb64 = (PBYTE)(*(DWORD64*)(teb64 + 0x60));

    DWORD NtGlobalFlag32, NtGlobalFlag64;

    // let's use offsets maybe
    // PEB32: BeingDebugged at 0x3, NtGlobalFlag at 0x68
    // PEB64: BeingDebugged at 0x3, NtGlobalFlag at 0xBC
    NtGlobalFlag32 = *(PDWORD)((PBYTE)peb32 + 0x68);
    NtGlobalFlag64 = *(PDWORD)((PBYTE)peb64 + 0xBC);

    // thanks hasherezade one day I'll send you a present
    FARPROC proc = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtWow64QueryInformationProcess64");
    if (proc == NULL) {
        exit(1);
    }
    NtWow64QueryInformationProcess64 = (NTSTATUS (NTAPI *)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG
    )) proc;

    PROCESS_BASIC_INFORMATION_WOW64 pbi64 = { 0 };
    ULONG outLength = 0;
    NTSTATUS status = NtWow64QueryInformationProcess64(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi64,
        sizeof(PROCESS_BASIC_INFORMATION_WOW64),
        &outLength
    );
    // TODO status check
    printf("PEB64: %x vs %x\n", peb64, pbi64.PebBaseAddress);

    printf("%d %d\n", NtGlobalFlag32, NtGlobalFlag64);
    return 0;
#endif
}