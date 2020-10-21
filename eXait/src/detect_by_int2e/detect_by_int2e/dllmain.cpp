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

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

#define MAX_ALLOWED 10

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

HMODULE hGlobalModule;

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by int 2e";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin detects Pin by executing the INT 0x2E instruction and checking the value returned in EDX (EIP).";
	return MyDescription;
}

DWORD GetEipByInt2e(void)
{
	DWORD MyEip = 0;

	// This technique was taken from the corkami project http://code.google.com/p/corkami/
	__asm
	{
		xor eax, eax;
		xor edx, edx;
		int 0x2e;
		mov MyEip, edx;
	}

	return MyEip;
}

BOOL IsWow64(HANDLE hProc)
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(hProc,&bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

int DoMyJob(void)
{
	// this is to prevent a crash under Wow64!
	if(IsWow64(GetCurrentProcess()))
		return PLATFORMNOTSUPPORTED;

	DWORD MyEip = GetEipByInt2e();
	MEMORY_BASIC_INFORMATION mbi;

	printf("MyRet is: %x\n", MyEip);

	VirtualQuery((LPCVOID)MyEip, &mbi, sizeof(mbi));

	printf("hGlobalModule is: %x -- AllocationBase is: %x\n", hGlobalModule, mbi.AllocationBase);

	if((DWORD)hGlobalModule == (DWORD)mbi.AllocationBase)
		return NOTDETECTED;
	else
		return DETECTED;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	hGlobalModule = hModule;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

