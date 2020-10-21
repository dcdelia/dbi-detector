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
#define TOUCHANDGO 2
#define MAX_COUNT 5
#define CANT_MODULES 10

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

void MyHook(void);

HMODULE hMods[CANT_MODULES] = {};
int count = 0;
DWORD index = 0;
DWORD Addr = 0;
BYTE bytes[5];
DWORD FuncAddr;

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by common API calls";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin hooks ZwAllocateVirtualMemory to check if it's being called by Pin";
	return MyDescription;
}

__declspec (naked) void MyHook(void)
{
	__asm
	{
		cmp dword ptr ss:[esp+0x14], 0x3000;
		jnz nosecomo;
		cmp dword ptr ss:[esp+0x18], 0x40;
		jnz nosecomo;
		inc count;

		nosecomo:
			mov eax, index;
			push Addr;
			ret;

	}
}

int HookZwAllocateVirtualMemory(void)
{
	DWORD Jmp, BytesRead, oldProtect, BytesWritten;
	BYTE toWrite[] = {0x0e9, 0x00, 0x00, 0x00, 0x00};
	void (*pfunc)() = MyHook;

	FuncAddr = (DWORD)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwAllocateVirtualMemory");
	if(FuncAddr)
	{
		if(ReadProcessMemory(GetCurrentProcess(), (LPVOID)FuncAddr, bytes, sizeof(bytes), &BytesRead))
		{
			index = (DWORD)bytes[1];

			if(VirtualProtect((LPVOID)FuncAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				Addr = FuncAddr + 5;

				Jmp = (DWORD)pfunc - (FuncAddr + 5);

				memcpy(toWrite+1, &Jmp, 4);

				if(WriteProcessMemory(GetCurrentProcess(), (LPVOID)FuncAddr, &toWrite, sizeof(toWrite), &BytesWritten))
					return 1;
			}
		}
	}
	return 0;
}

void FreeModules(void)
{
	int i;

	for(i=0;i<CANT_MODULES;i++)
	{
		if(hMods[i])
			FreeLibrary(hMods[i]);
	}
}

int DoMyJob(void)
{
	DWORD BytesWritten;

	HookZwAllocateVirtualMemory();

	char *MyDlls[] = {"user32.dll", "ntmarta.dll", "gdi32.dll", "advapi32.dll", "comctl32.dll",
						"comdlg32.dll", "crypt32.dll", "dbghelp.dll", "ole32.dll", "urlmon.dll"};
	int i;

	for(i=0;i<CANT_MODULES;i++)
	{
		hMods[i] = LoadLibrary(MyDlls[i]);
		printf("Loaded %s at: %08X\n", MyDlls[i], hMods[i]);
	}

	printf("[+] Count is: %d\n", count);

	// restore original bytes
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)FuncAddr, &bytes, 5 , &BytesWritten);

	// free loaded modules
	FreeModules();

	if(count > MAX_COUNT)
		return DETECTED;
	return NOTDETECTED;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
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

