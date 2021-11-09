#include <algorithm>
#include <codecvt>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef WIN32
#   error "This application must be built as an x86 executable"
#endif

#define GET_FUNC_ADDR(name) _##name name = (_##name)::GetProcAddress(::GetModuleHandleA("ntdll.dll"), #name)

#define IS_TRUE(clause, msg) if (!(clause)) { throw std::runtime_error(msg); }

#include <windows.h>

#define NT_SUCCESS(x) ((x) >= 0)

// Namespace is present Not to collide with "winbase.h"
// definition of PROCESS_INFORMATION_CLASS and others.
namespace sys
{

typedef enum _PROCESS_INFORMATION_CLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;

// ------------------------------------------------------------------------
// Structs.
// ------------------------------------------------------------------------

typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONGLONG Reserved1;
    ULONGLONG PebBaseAddress;
    ULONGLONG Reserved2[2];
    ULONGLONG UniqueProcessId;
    ULONGLONG Reserved3;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PEB_LDR_DATA64 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONGLONG SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

// Structure is cut down to ProcessHeap.
typedef struct _PEB64 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    ULONGLONG Mutant;
    ULONGLONG ImageBaseAddress;
    ULONGLONG LoaderData;
    ULONGLONG ProcessParameters;
    ULONGLONG SubSystemData;
    ULONGLONG ProcessHeap;
} PEB64;

typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} UNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONGLONG BaseAddress;
    ULONGLONG EntryPoint;
    DWORD64 SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY64 HashTableEntry;
    ULONGLONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

}  // namespace sys

// ------------------------------------------------------------------------
// Function prototypes.
// ------------------------------------------------------------------------

typedef NTSTATUS(NTAPI *_NtWow64QueryInformationProcess64)(
    IN HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI *_NtWow64ReadVirtualMemory64)(
    IN HANDLE ProcessHandle,
    IN DWORD64 BaseAddress,
    OUT PVOID Buffer,
    IN ULONG64 Size,
    OUT PDWORD64 NumberOfBytesRead);


namespace
{

struct close_on_exit
{
    close_on_exit(HANDLE ptr)
        : ptr_(ptr)
    { };

    ~close_on_exit()
    {
        if (ptr_)
        {
            ::CloseHandle(ptr_);
            ptr_ = nullptr;
        }
    }

private:
    HANDLE ptr_;
};

// Names of modules 
std::string convert_unicode_to_utf8(std::vector<uint8_t> &raw_bytes)
{
    std::vector<uint16_t> unicode(raw_bytes.size() >> 1, 0);
    memcpy(unicode.data(), raw_bytes.data(), raw_bytes.size());

    char ktm[256];
    wsprintf(ktm, "%s", unicode.data());
    return std::string(ktm);
    
    /*std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

    const std::wstring wide_string(unicode.begin(), unicode.end());
    const std::string utf8_string = converter.to_bytes(wide_string);

    return utf8_string;*/
}

void *get_handle(uint32_t id)
{
    HANDLE handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    std::cout << "Opening target process...";

    IS_TRUE(NULL != handle, "OpenProcess failed");

    std::cout << " ok" << std::endl;

    return handle;
}

void check_if_process_is_x64(HANDLE handle)
{
    BOOL is_wow64_process = TRUE;
    IS_TRUE(::IsWow64Process(handle, &is_wow64_process), "IsWow64Process failed");
    IS_TRUE(FALSE == is_wow64_process, "Target process is not x64 one");
}

std::vector<uint8_t> read_mem(HANDLE handle, uint64_t address, uint32_t length)
{
    IS_TRUE(handle, "No process handle obtained");

    std::vector<uint8_t> data(length, 0);

    GET_FUNC_ADDR(NtWow64ReadVirtualMemory64);

    NTSTATUS status = NtWow64ReadVirtualMemory64(handle, address, data.data(), data.size(), FALSE);

    IS_TRUE(NT_SUCCESS(status), "NtWow64ReadVirtualMemory64 failed");

    return data;
}

void read_pbi(HANDLE handle, sys::PROCESS_BASIC_INFORMATION64 &pbi)
{
    IS_TRUE(handle, "No process handle obtained");

    GET_FUNC_ADDR(NtWow64QueryInformationProcess64);

    NTSTATUS status = NtWow64QueryInformationProcess64(handle, sys::ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    IS_TRUE(NT_SUCCESS(status), "NtQueryInformationProcess failed");
}

std::vector<uint8_t> read_peb_data(HANDLE handle)
{
    sys::PROCESS_BASIC_INFORMATION64 pbi = { 0 };
    read_pbi(handle, pbi);

    return read_mem(handle, pbi.PebBaseAddress, sizeof(sys::PEB64));
}

bool get_modules_load_order_via_peb(HANDLE handle)
{
    std::cout << "Getting module load order...\n" << std::endl;

    //std::vector<uint8_t> read_peb = read_peb_data(handle);
    //sys::PEB64 *peb = (sys::PEB64 *)read_peb.data();
    BYTE* teb32;
    __asm__ volatile(
        ".intel_syntax noprefix ;"
        "mov %0, dword ptr fs:[0x18] ;"
        ".att_syntax noprefix ;"
        : "+r"(teb32) : :
    );
    BYTE* teb64 = teb32 - 0x2000;
	//BYTE* peb32 = (BYTE*)(*(DWORD*)(teb32 + 0x30));
	sys::PEB64 *peb = (sys::PEB64*)(*(DWORD64*)(teb64 + 0x60));


    // ------------------------------------------------------------------------
    // Read memory from pointer to loader data structures.
    // ------------------------------------------------------------------------
    std::vector<uint8_t> read_peb_ldr_data = read_mem(handle, (uintptr_t)peb->LoaderData, sizeof(sys::PEB_LDR_DATA64));
    sys::PEB_LDR_DATA64 *peb_ldr_data = (sys::PEB_LDR_DATA64 *)read_peb_ldr_data.data();
    sys::PEB_LDR_DATA64 *loader_data = (sys::PEB_LDR_DATA64 *)peb->LoaderData;

    const uintptr_t addr_of_ptr_to_first_ldr_module = (uintptr_t)loader_data
        + ((uintptr_t)&loader_data->InLoadOrderModuleList - (uintptr_t)&loader_data->Length);

    ULONGLONG address = peb_ldr_data->InLoadOrderModuleList.Flink;

    uint32_t counter = 1;

    // ------------------------------------------------------------------------
    // Traversing loader data structures.
    // ------------------------------------------------------------------------
    do
    {
        std::vector<uint8_t> read_ldr_table_entry = read_mem(handle, address, sizeof(sys::LDR_DATA_TABLE_ENTRY64));

        sys::LDR_DATA_TABLE_ENTRY64 *ldr_table_entry = (sys::LDR_DATA_TABLE_ENTRY64 *)read_ldr_table_entry.data();

        std::vector<uint8_t> unicode_name = read_mem(handle, ldr_table_entry->BaseDllName.Buffer, ldr_table_entry->BaseDllName.MaximumLength);
        //std::string name = convert_unicode_to_utf8(unicode_name);

        //char ktm[256];
        wprintf(L"%s", ldr_table_entry->BaseDllName.Buffer);
        std::string name = std::string("morte al re");

        std::cout << "Module: " << name << std::endl;
        std::cout << "  Image base: 0x" << std::hex << ldr_table_entry->BaseAddress << std::endl;

        ldr_table_entry = (sys::LDR_DATA_TABLE_ENTRY64 *)read_ldr_table_entry.data();
        address = (uintptr_t)ldr_table_entry->InLoadOrderModuleList.Flink;
    } while (addr_of_ptr_to_first_ldr_module != address);

    std::cout << "\nEnumeration finished" << std::endl;

    return true;
}

}  // namespace

int main()
{

    HANDLE handle = GetCurrentProcess(); //get_handle(16944);
    close_on_exit auto_close_handle(handle);

    /*check_if_process_is_x64(handle);*/
    get_modules_load_order_via_peb(handle);
    return 0;
}