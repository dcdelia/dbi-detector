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
	static char PluginName[] = "Detect Pin by page permissions";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin looks for memory pages with EXECUTE+READ+WRITE permissions, typically allocated by Pin to store code generated by the JIT compiler.";
	return MyDescription;
}

DWORD CountRWEPages()
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBytes;
	DWORD MyAddress = 0;
	DWORD rweCont = 0;

	do
	{
		numBytes = VirtualQuery((LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT) && (mbi.Protect == PAGE_EXECUTE_READWRITE))
		{
			//printf("BaseAddress: %x\n", mbi.BaseAddress);
			//printf("Size: %x\n", mbi.RegionSize);
			rweCont++;
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return rweCont;
}

int DoMyJob(void)
{

	DWORD cont;

	cont = CountRWEPages();

	printf("Number of pages with EXECUTE+READ+WRITE: %d\n", cont);

	if(cont > MAX_ALLOWED) // arbitrary number
		return DETECTED;
	else
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
