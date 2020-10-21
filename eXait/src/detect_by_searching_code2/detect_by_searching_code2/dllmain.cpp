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

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

long long FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);

char pattern1[] = "\xCD\x01"           				// INT 1
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x02"           			// INT 2
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x03"           			// INT 3
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x04"           			// INT 4
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x05"           			// INT 5
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x06"           			// INT 6
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x07"           			// INT 7
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x08"           			// INT 8
					"\xE9\x00\x00\x00\x00"     		// JMP 01750922
					"\x90"              			// NOP
					"\xCD\x09"           			// INT 9
					"\xE9\x00\x00\x00\x00";    		// JMP 01750922


char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by searching a code pattern";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin searches for a code pattern usually located in the heap";
	return MyDescription;
}

int CountRWEPages()
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBytes;
	DWORD MyAddress = 0;
	DWORD rweCont = 0;
	long long find;
	BYTE wildcard = 0;

	do
	{
		numBytes = VirtualQuery((LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT) && (mbi.Protect == PAGE_EXECUTE_READWRITE))
		{
			//printf("BaseAddress: %x\n", mbi.BaseAddress);
			//printf("Size: %x\n", mbi.RegionSize);
			rweCont++;

			find = FindEx(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, pattern1, strlen(pattern1), &wildcard);
			if(find)
				return DETECTED;
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return NOTDETECTED;
}

// This piece of code belongs to the TitanEngine framework http://www.reversinglabs.com/products/TitanEngine.php
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

int DoMyJob(void)
{
	return CountRWEPages();
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