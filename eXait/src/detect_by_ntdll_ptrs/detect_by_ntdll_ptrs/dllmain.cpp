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

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin ntdll.dll pointers";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin looks for four pointers to ntdll.dll functions at the beginning of every memory page in the following order:\n 1 - LdrLoadDll\n 2 - LdrGetProcedureAddress\n 3 - ZwSignalAndWaitForSingleObject\n 4 - ZwClose";
	return MyDescription;
}

int SearchNtdllPtrs()
{
	int i;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBytes;
	DWORD MyAddress = 0;
	char* FuncNames[] = {"LdrLoadDll", "LdrGetProcedureAddress", "ZwSignalAndWaitForSingleObject", "ZwClose"};
	DWORD Addrs[sizeof(FuncNames)/sizeof(FuncNames[0])];
	DWORD* MyPtr;
	int cant;

	for(i=0; i < sizeof(FuncNames)/sizeof(FuncNames[0]); i++)
		Addrs[i] = (DWORD)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), FuncNames[i]);

	do
	{
		numBytes = VirtualQuery((LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if(mbi.State == MEM_COMMIT)
		{
			MyPtr = (DWORD*)mbi.BaseAddress;

			cant = 0;
			for(i=0; i <  sizeof(FuncNames)/sizeof(FuncNames[0]); i++)
			{
				if((DWORD)Addrs[i] == *MyPtr)
					cant++;
				
				MyPtr++;
			}

			if(cant == sizeof(FuncNames)/sizeof(FuncNames[0]))
				return DETECTED;
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return NOTDETECTED;
}

int DoMyJob(void)
{
	return SearchNtdllPtrs();
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

