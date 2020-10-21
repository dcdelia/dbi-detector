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

// detect_by_time.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#define DllExport extern "C" __declspec(dllexport)

#define MAX_TIME 100
#define	NOTDETECTED 0
#define DETECTED 1
#define CANT_MODULES 10

DllExport char* GetPluginName();
DllExport char* GetPluginDescription();
DllExport int DoMyJob();


char* GetPluginName()
{
	static char PluginName[] = "Detect Pin by time";
	return PluginName;
}



char* GetPluginDescription()
{
	static char MyDescription[] = "This plugin tries to detect Pin by checking execution time, based on the fact that Pin adds an overhead when its JIT compiler generates code.";
	return MyDescription;
}


HMODULE hMods[CANT_MODULES] = {};

void MakeTheJITWork()
{
	char *MyDlls[] = {"user32.dll", "ntmarta.dll", "gdi32.dll", "advapi32.dll", "comctl32.dll",
						"comdlg32.dll", "crypt32.dll", "dbghelp.dll", "ole32.dll", "urlmon.dll"};
	int i;

	for(i=0;i<CANT_MODULES;i++)
	{
		hMods[i] = LoadLibrary(MyDlls[i]);
		printf("Loaded %s at: %08X\n", MyDlls[i], hMods[i]);
	}

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

int DoMyJob()
{
	DWORD time1, time2;
	time1 = GetTickCount();
	MakeTheJITWork();
	time2 = GetTickCount();

	FreeModules();

	printf("Execution time: %d\n", time2 - time1);
	return time2 - time1 > MAX_TIME? DETECTED: NOTDETECTED;
}