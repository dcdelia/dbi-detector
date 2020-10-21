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

#define DllExport extern "C" __declspec(dllexport)

#pragma comment(lib, "Psapi.lib")

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

int EnumMyModules(void);

char* GetPluginName(void)
{
	static char PluginName[] = "Detect pinvm Dll";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "Looks for the pinvm.dll into the list of loaded modules";
	return MyDescription;
}

void lowercase(char string[])
{
   int  i = 0;

   while ( string[i] )
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
    unsigned int i;
    char szModName[MAX_PATH];
	DWORD processID;

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

            // Get the full path to the module's file.

            if(GetModuleFileName(hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)))
            {
				lowercase(szModName);

				// printf("\t%s\t(0x%08X)\n", szModName, hMods[i]);
				
                // Print the module name and handle value.
				printf("%s\n", szModName);
				if(strstr(szModName, "pinvm.dll") != NULL)
				{
					return 1;
				}

            }

        }

    }

    CloseHandle(hProcess);
	return 0;
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

