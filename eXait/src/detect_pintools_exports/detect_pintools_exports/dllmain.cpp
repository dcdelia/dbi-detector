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

#pragma comment(lib, "Psapi.lib")

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

int EnumMyModules(void);

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pintools Exports";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "Looks for functions exported by the pintools";
	return MyDescription;
}

int EnumMyModules(void)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    //char szModName[MAX_PATH];
	DWORD processID;

	processID = GetCurrentProcessId();

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );

    if (hProcess == NULL)
    {
		printf("OpenProcess() failed! Error %d\n", GetLastError());
		return PLUGINERROR;
    }

    if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for(i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
			if(GetProcAddress(hMods[i], "CharmVersionC"))
				return DETECTED;
			else if (GetProcAddress(hMods[i], "ClientIntC"))
				return DETECTED;
        }

    }

    CloseHandle(hProcess);
	return NOTDETECTED;
}

int DoMyJob(void)
{
	return EnumMyModules();
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
