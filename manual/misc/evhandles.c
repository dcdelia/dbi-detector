/*
Copyright (c) 2012, Core Security Technologies
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

// code from http://forum.sysinternals.com/uploads/26792/handles.zip
// $Id: dllmain.cpp 50 2012-03-01 19:27:22Z ncr $

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
int IsPinNameHandleInCurrentProcess(void);

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

int IsPinNameHandleInCurrentProcess(void)
{
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    ULONG pid;
    HANDLE processHandle;
    ULONG i;
	BOOL ProcessHandle = FALSE, PinInHandle = FALSE;

    pid = GetCurrentProcessId();

    if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
    {
        return PLUGINERROR;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	if(handleInfo == NULL)
		return PLUGINERROR;

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleInfoSize = handleInfoSize * 2;

        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
		if(handleInfo == NULL)
			return PLUGINERROR;
	}

    if (!NT_SUCCESS(status))
    {
		free(handleInfo);
        return PLUGINERROR;
    }

    for (i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        if (handle.ProcessId != pid)
            continue;

        if (!NT_SUCCESS(NtDuplicateObject(
            processHandle,
            (HANDLE)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0
            )))
        {
            continue;
        }

        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
            )))
        {
            CloseHandle(dupHandle);
            continue;
        }

        if (handle.GrantedAccess == 0x0012019f)
        {
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
            )))
        {
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
                )))
            {
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        objectName = *(PUNICODE_STRING)objectNameInfo;

        if (objectName.Length)
        {
			wprintf(L"%s\t%s\n", objectTypeInfo->Name.Buffer, objectName.Buffer);
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    VirtualFree(handleInfo, 0, MEM_RELEASE);
    CloseHandle(processHandle);

	if (ProcessHandle && PinInHandle)
		return DETECTED;
	else
		return NOTDETECTED;
}

int main(void)
{
	IsPinNameHandleInCurrentProcess();
    return 0;
}