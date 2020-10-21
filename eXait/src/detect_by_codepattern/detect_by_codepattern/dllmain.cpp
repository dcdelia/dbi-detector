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
#define MAX_MODULES 1024

#pragma comment(lib, "Psapi.lib")

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

long long FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);

char code_pattern[] = "\x89\x74\x24\x04"		 // MOV DWORD PTR SS:[ESP+4],ESI
						"\x89\x5C\x24\x10"       // MOV DWORD PTR SS:[ESP+10],EBX
						"\x89\x54\x24\x14"       // MOV DWORD PTR SS:[ESP+14],EDX
						"\x89\x4C\x24\x18"       // MOV DWORD PTR SS:[ESP+18],ECX
						"\x89\x44\x24\x1C"       // MOV DWORD PTR SS:[ESP+1C],EAX
						"\x33\xC0"				 // XOR EAX,EAX
						"\x89\x44\x24\x20"       // MOV DWORD PTR SS:[ESP+20],EAX
						"\x8C\x4C\x24\x20"       // MOV WORD PTR SS:[ESP+20],CS
						"\x89\x44\x24\x28"       // MOV DWORD PTR SS:[ESP+28],EAX
						"\x8C\x5C\x24\x28"       // MOV WORD PTR SS:[ESP+28],DS
						"\x89\x44\x24\x24"       // MOV DWORD PTR SS:[ESP+24],EAX
						"\x8C\x54\x24\x24"       // MOV WORD PTR SS:[ESP+24],SS
						"\x89\x44\x24\x2C"       // MOV DWORD PTR SS:[ESP+2C],EAX
						"\x8C\x44\x24\x2C"       // MOV WORD PTR SS:[ESP+2C],ES
						"\x89\x44\x24\x30"       // MOV DWORD PTR SS:[ESP+30],EAX
						"\x8C\x64\x24\x30"       // MOV WORD PTR SS:[ESP+30],FS
						"\x89\x44\x24\x34"       // MOV DWORD PTR SS:[ESP+34],EAX
						"\x8C\x6C\x24\x34";      //MOV WORD PTR SS:[ESP+34],GS

HMODULE hGlobalModule;

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by searching code patterns";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin implements a search function to search for a code pattern.";
	return MyDescription;
}

int EnumMyModules(HMODULE* hMods)
{
    HANDLE hProcess;
    DWORD cbNeeded;
	DWORD processID;
	int retval;

	processID = GetCurrentProcessId();

    printf("\nProcess ID: %u\n", processID);

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );

    if (hProcess == NULL)
    {
        printf("OpenProcess() failed! Error %d\n", GetLastError());
		return -1;
    }

    retval = EnumProcessModules(hProcess, hMods, sizeof(hMods) * MAX_MODULES, &cbNeeded);

    CloseHandle(hProcess);
	return (cbNeeded/sizeof(HMODULE));
}

int FindPattern(char *MyPattern)
{
	HMODULE hMods[MAX_MODULES];
	int i, cant_mods;
	BOOL retval;
	MODULEINFO mi;
	long long find;
	
	cant_mods = EnumMyModules(hMods);

	for(i=0;i<cant_mods;i++)
	{
		if(hMods[i] != hGlobalModule)
		{
			retval = GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi)); 
			find = FindEx(GetCurrentProcess(), hMods[i], mi.SizeOfImage, MyPattern, strlen(MyPattern), NULL);
			if(find)
				return DETECTED;
		}
	}

	return NOTDETECTED;
}

int DoMyJob(void)
{
	int retval, i;

	char* PatternArray[] = {code_pattern};

	for(i=0;i < sizeof(PatternArray)/sizeof(PatternArray[0]);i++)
	{
		printf("Searching for pattern ...");
		retval = FindPattern(PatternArray[i]);
		if(retval == DETECTED)
		{
			printf("Pattern found!\n");
			return DETECTED;
		}
	}
	return NOTDETECTED;
}

// This code belongs to the TitanEngine framework http://www.reversinglabs.com/products/TitanEngine.php
long long FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard){

	int i = NULL;
	int j = NULL;
	ULONG_PTR Return = NULL;
	LPVOID ueReadBuffer = NULL;
	PUCHAR SearchBuffer = NULL;
	PUCHAR CompareBuffer = NULL;
	ULONG_PTR ueNumberOfBytesRead = NULL;
	LPVOID currentSearchPosition = NULL;
	DWORD currentSizeOfSearch = NULL;
	BYTE nWildCard = NULL;

	if(WildCard == NULL){WildCard = &nWildCard;}
	if(hProcess != NULL && MemoryStart != NULL && MemorySize != NULL){
		if(hProcess != GetCurrentProcess()){
			ueReadBuffer = VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
			if(!ReadProcessMemory(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead)){
				VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
				return(NULL);
			}else{
				SearchBuffer = (PUCHAR)ueReadBuffer;
			}
		}else{
			SearchBuffer = (PUCHAR)MemoryStart;
		}
		__try{
			CompareBuffer = (PUCHAR)SearchPattern;
			for(i = 0; i < (int)MemorySize && Return == NULL; i++){
				for(j = 0; j < (int)PatternSize; j++){
					if(CompareBuffer[j] != *(PUCHAR)WildCard && SearchBuffer[i + j] != CompareBuffer[j]){
						break;
					}
				}
				if(j == (int)PatternSize){
					Return = (ULONG_PTR)MemoryStart + i;
				}
			}
			VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(Return);
		}__except(EXCEPTION_EXECUTE_HANDLER){
			VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(NULL);
		}
	}else{
		return(NULL);
	}
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

