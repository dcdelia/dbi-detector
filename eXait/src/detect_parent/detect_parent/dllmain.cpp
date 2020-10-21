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

// our error codes
#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

#define DllExport extern "C" __declspec(dllexport)

DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

#define MAX_PIDS 1024

DWORD pIds[MAX_PIDS] = {-1};

char* GetPluginName(void)
{
	static char PluginName[] = "Detect parent process";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin checks the name of the parent process."
								  "If it does not match \"explorer.exe\" nor \"cmd.exe\", "
								  "it assumes that it is being instrumented.";
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

int GetNameByPid(DWORD pid, char* ProcName, DWORD ProcNameBuffSize)
{
	HINSTANCE hInstLib;
	HANDLE hSnapShot;
	BOOL bContinue;
	PROCESSENTRY32 procentry;

	HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD);
	BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32);
	BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32);

	hInstLib = LoadLibraryA( "Kernel32.DLL" ) ;
	if( hInstLib == NULL )
	{
		printf("Unable to load Kernel32.dll\n");
		return FALSE ;
	}

	lpfCreateToolhelp32Snapshot= (HANDLE(WINAPI *)(DWORD,DWORD))
	GetProcAddress( hInstLib, "CreateToolhelp32Snapshot" );

	lpfProcess32First= (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
	GetProcAddress( hInstLib, "Process32First" );
	 
	lpfProcess32Next= (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
	GetProcAddress( hInstLib, "Process32Next" );
	 
	if( lpfProcess32Next == NULL || lpfProcess32First == NULL || lpfCreateToolhelp32Snapshot == NULL )
	{
		FreeLibrary( hInstLib );
		return FALSE ;
	}

	hSnapShot = lpfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
	if( hSnapShot == INVALID_HANDLE_VALUE )
	{
		 printf("ERROR: INVALID_HANDLE_VALUE");
		 FreeLibrary( hInstLib );
		 return FALSE;
	}

	memset((LPVOID)&procentry,0,sizeof(PROCESSENTRY32));

	procentry.dwSize = sizeof(PROCESSENTRY32);
	bContinue = lpfProcess32First( hSnapShot, &procentry );

	while(bContinue)
	{
		if(pid == procentry.th32ProcessID)
		{
			strncpy_s(ProcName, ProcNameBuffSize, procentry.szExeFile, ProcNameBuffSize);
			return 1;
		}

		procentry.dwSize = sizeof(PROCESSENTRY32);
		bContinue = lpfProcess32Next(hSnapShot, &procentry);

	}
	
	return 0;
}

int IsParentExplorerOrCmd(void)
{
	HINSTANCE hInstLib;
	HANDLE hSnapShot;
	BOOL bContinue;
	DWORD crtpid, pid = 0;
	PROCESSENTRY32 procentry;

	char ProcName[MAX_PATH];

	HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD);
	BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32);
	BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32);

	hInstLib = LoadLibraryA( "Kernel32.DLL" ) ;
	if( hInstLib == NULL )
	{
		printf("Unable to load Kernel32.dll\n");
		return FALSE ;
	}

	lpfCreateToolhelp32Snapshot= (HANDLE(WINAPI *)(DWORD,DWORD))
	GetProcAddress( hInstLib, "CreateToolhelp32Snapshot" );

	lpfProcess32First= (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
	GetProcAddress( hInstLib, "Process32First" );
	 
	lpfProcess32Next= (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
	GetProcAddress( hInstLib, "Process32Next" );
	 
	if( lpfProcess32Next == NULL || lpfProcess32First == NULL || lpfCreateToolhelp32Snapshot == NULL )
	{
		FreeLibrary( hInstLib );
		return FALSE ;
	}

	hSnapShot = lpfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
	if( hSnapShot == INVALID_HANDLE_VALUE )
	{
		 printf("ERROR: INVALID_HANDLE_VALUE");
		 FreeLibrary( hInstLib );
		 return FALSE;
	}

	memset((LPVOID)&procentry,0,sizeof(PROCESSENTRY32));

	procentry.dwSize = sizeof(PROCESSENTRY32);
	bContinue = lpfProcess32First( hSnapShot, &procentry );

	crtpid = GetCurrentProcessId();
	while(bContinue)
	{
		//printf("-- Process name: %s -- Process ID: %d -- Parent ID: %d\n", procentry.szExeFile, procentry.th32ProcessID, procentry.th32ParentProcessID);

		if(crtpid == procentry.th32ProcessID)
		{
			//__asm{int 3};

			pid =  procentry.th32ParentProcessID;
			
			lowercase(procentry.szExeFile);
			
			FreeLibrary(hInstLib);
			
			GetNameByPid(procentry.th32ParentProcessID, ProcName, sizeof(ProcName));
			printf("%s\n", ProcName);

			if(strcmp("explorer.exe", ProcName) && strcmp("cmd.exe", ProcName))
				return DETECTED;
			else
				return NOTDETECTED;

		}

		procentry.dwSize = sizeof(PROCESSENTRY32);
		bContinue = !pid && lpfProcess32Next( hSnapShot, &procentry );

	}

	FreeLibrary(hInstLib);
	return PLUGINERROR;
}

int DoMyJob(void)
{
	return IsParentExplorerOrCmd();
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

