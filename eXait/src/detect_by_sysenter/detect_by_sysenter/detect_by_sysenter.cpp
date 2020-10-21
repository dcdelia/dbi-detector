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

// detect_by_sysenter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

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

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by sysenter";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "Detects Pin by executing a sysenter instruction. Pin does not properly handle this instruction; when returning from Ring 0 to Ring 3 after the syscall, a normal execution should continue at ntdll!KiFastSystemCallRet, but when being instrumented by Pin it continues at the instruction following the sysenter. This plugin works with Pin versions prior to build 41150 (Jun 07, 2011).";
	return MyDescription;
}

// This technique is based on a bug discovered by Eloi Vanderbeken and reported in the
// Pin's mailing list http://tech.groups.yahoo.com/group/pinheads/message/6363
int DoMyJob()
{
	int detected;

	// this is to prevent a crash under Wow64!
	if(IsWow64(GetCurrentProcess()))
		return PLATFORMNOTSUPPORTED;
	__asm{
		mov eax, 0x42424242;		//invalid syscall
		push retaddress;
		mov edx, esp;
		//Sysenter
		_emit 0x0F;
		_emit 0x34;
		mov detected, DETECTED;		//if execution reaches here, it means that it's being instrumented
		jmp endasm;
retaddress:
		mov detected, NOTDETECTED;	//normal execution should continue here after the sysenter
endasm:
	}
	return detected;

}



int main(int argc, char* argv[])
{
	return 0;
}

