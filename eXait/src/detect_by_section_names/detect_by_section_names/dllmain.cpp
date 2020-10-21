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

bool isEqual(char*, char*);

char* GetPluginName(void)
{
	static char PluginName[] = "Detect Pin by searching PE section names";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin detects Pin by searching PE section names in both pinvm.dll and the pintool";
	return MyDescription;
}

void lowercase(char string[])
{
   int  i = 0;

   while ( i < 8 )
   {
      string[i] = tolower(string[i]);
      i++;
   }
}

int EnumMyModules(void)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i,j;
	DWORD processID;
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS32 nthdr;
	PIMAGE_SECTION_HEADER sectionhdr;
	DWORD nro_sections;
	char AuxName[8];

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
				//printf("[+] Section Name: %s\n", sectionhdr->Name);

				memcpy(AuxName, sectionhdr->Name, 8);
				lowercase(AuxName);

				if((isEqual(AuxName, ".charmveC")) || (isEqual(AuxName, ".pinclie")))
				{
					//system("pause");
					return DETECTED;
				}
				sectionhdr = (PIMAGE_SECTION_HEADER)((char*)sectionhdr + sizeof(IMAGE_SECTION_HEADER));
			}
			
		}
    }

    CloseHandle(hProcess);
	return NOTDETECTED;
}

bool isEqual(char* str1, char* str2)
{
	int i;

	for(i=0; i < 8; i++)
	{
		if(str1[i] != str2[i])
			return false;
	}

	return true;
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

