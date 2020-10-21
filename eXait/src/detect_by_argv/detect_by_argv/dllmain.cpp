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
	static char PluginName[] = "Detect Pin by argv";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "Detects Pin by searching for the original argv variable in memory";
	return MyDescription;
}

int EnumMyModules(void)
{
	unsigned int i, j, cont = 0;
    HMODULE hMods[1024];
    HANDLE hProcess;
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS32 nthdr;
	PIMAGE_SECTION_HEADER sectionhdr;
	DWORD nro_sections, MyPtr, cbNeeded, processID;
	DWORD* argvptr;

	processID = GetCurrentProcessId();

    // Print the process identifier.

    printf("\nProcess ID: %u\n", processID);

 
    // Get a list of all the modules in this process.

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );

    if (hProcess == NULL)

      {

        printf("OpenProcess() failed! Error %d\n", GetLastError());
		return -1;

      }

    if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))

    {
        for(i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {

			doshdr = (PIMAGE_DOS_HEADER)hMods[i];
			//printf("DOS_HEADER: %p\n", doshdr);

			nthdr = (PIMAGE_NT_HEADERS32)((char*)(doshdr->e_lfanew + (LONG)hMods[i]));
			//printf("NT_HEADER: %p\n", nthdr);

			nro_sections = nthdr->FileHeader.NumberOfSections;
			//printf("[+] Number of Sections: %d\n", nro_sections);


			sectionhdr = (PIMAGE_SECTION_HEADER)((char*)nthdr + sizeof(IMAGE_NT_HEADERS32));
			//printf("SECTION_HEADER: %p\n", sectionhdr);

			for(j=0; j < nro_sections; j++)
			{
				MyPtr = sectionhdr->VirtualAddress + (DWORD)hMods[i];

				if(*((DWORD*)MyPtr) == 0xDEADBEEF) // DEADBEEF
				{
					argvptr = (DWORD*)(*((DWORD*)MyPtr + 1));
					
					while(*argvptr != 0)
					{
						printf("[+] String: %s\n", (char*)(*argvptr));

						if((!strcmp((char*)*argvptr, "-t")) || (!strcmp((char*)*argvptr, "--")) || (!strcmp((char*)*argvptr, "-pid")))
						{
							cont++;

							if(cont >= 2)
								return DETECTED;
						}
						argvptr++;
					}
				}
				sectionhdr = (PIMAGE_SECTION_HEADER)((char*)sectionhdr + sizeof(IMAGE_SECTION_HEADER));
			}

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

