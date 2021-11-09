// credits: CheckPoint research anti-debug
// however the one from FKIE-AntiRE works?!?!?
#include <windows.h>
#include <ntdef.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI * _NtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

_NtQueryInformationProcess NtQueryInformationProcess;

int main() {
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetLibraryProcAddress("ntdll.dll", "NtQueryInformationProcess");

    if (!NtQueryInformationProcess)
        return 1;

    DWORD dwReturned;
    HANDLE hProcessDebugObject = 0;
    const DWORD ProcessDebugObjectHandle = 0x1e;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &hProcessDebugObject,
        sizeof(HANDLE),
        &dwReturned);

    // C0000353	STATUS_PORT_NOT_SET
    if (NT_SUCCESS(status)) {
        printf("Output handle: %p\n", hProcessDebugObject);
    } else {
        printf("Failed! Status: %p\n", status);
    }

    // let's try ProcessDebugPort
    const DWORD ProcessDebugPort = 0x7;
    DWORD dwProcessDebugPort;
    status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &dwProcessDebugPort,
            sizeof(DWORD),
            &dwReturned);
    if (NT_SUCCESS(status)) {
        printf("Output port: %d\n", dwProcessDebugPort);
    } else {
        printf("Failed! Status: %p\n", status);
    }

    return 0;
}