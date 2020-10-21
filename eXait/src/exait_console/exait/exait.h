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

#include "stdafx.h"

#define MAX_PLUGINS 1024
#define FUNCADDRERR -2

int LoadPlugins(char *PluginsPath);
int ExecutePlugin(HMODULE hPlugin);
int ListAvailablePlugins(char*);

char* GetPluginsFolder(void);
char* CallGetPluginName(HMODULE hPlugin);
char* CallGetPluginDescription(HMODULE hPlugin);

void PrintCredits(void);
void PrintUsage(void);
void ValidateResult(int, char*);

HMODULE LoadPlugin(char*);

typedef int (__stdcall *DOMYJOB)(void);
typedef char* (__stdcall *GETPLUGINNAME)(void);
typedef char* (__stdcall *GETPLUGINDESCRIPTION)(void);

HMODULE PluginArray[MAX_PLUGINS] = {(HMODULE)-1};

void ValidateResult(int result, char* pName)
{
	if(result)
		printf("\n[+] Pin detected with %s!\n\n", pName);
	else
		printf("\n[-] Pin not detected with %s!\n\n", pName);
}

int ListAvailablePlugins(char* PluginsFolder)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE retval;
	int cont = 0;

	SetCurrentDirectory(PluginsFolder);

	retval = FindFirstFile("*.dll", &FindFileData);
	if((retval != INVALID_HANDLE_VALUE) && ((long)retval != ERROR_FILE_NOT_FOUND))
	{
		do
		{
			printf("Plugin dll name: %s\n", FindFileData.cFileName);
			cont++;
		}while(FindNextFile(retval, &FindFileData) != 0);
	}
	
	return cont;
}

void PrintCredits(void)
{

	system("cls");
	printf("************************************************************\n");
	printf("****** eXait - eXtensible Anti-Instrumentation Tester ******\n");
	printf("************************************************************\n\n");
	printf("Coded by: Francisco Falcon & Nahuel Riva from Core Security Technologies\n");
	printf("Buenos Aires - Argentina\n\n");
}

void PrintUsage(void)
{
	printf("Usage: exait.exe <options>\n\n");
	printf("Options:\n\n");
	printf("-l: List all available plugins\n");
	printf("-a: Executes all the available plugins\n");
	printf("-n: <name of the plugin dll> Gets the name of the Plugin (i.e: detect_by_eip.dll)\n");
	printf("-d: <name of the plugin dll> Gets description of the Plugin (i.e: detect_by_eip.dll)\n");
	printf("-p: <name of the plugin dll> Executes the specified plugin (i.e: detect_by_eip.dll)\n");
	printf("-s: <list of plugins> Loads the plugins indicated in <list of plugins> ((i.e: detect_by_eip.dll detect_by_argv.dll ...))\n");
	printf("-f: <filename.txt> Loads a file name with a list of plugins to load (i.e: blah.txt)\n");
	printf("-h: Prints this help\n\n");
}

char* GetPluginsFolder(void)
{
	static char PluginsFolderPath[MAX_PATH];

	char CurrentDir[MAX_PATH];

	memset(PluginsFolderPath, 0, sizeof(PluginsFolderPath));
	memset(CurrentDir, 0, sizeof(CurrentDir));

	GetModuleFileName(NULL, CurrentDir, sizeof(CurrentDir));

	int CurDirLen = strlen(CurrentDir);

	while(*(char *)(CurrentDir+CurDirLen) != '\\')
	{
		*(char *)(CurrentDir+CurDirLen) = '\0';
		CurDirLen --;
	}

	size_t FreeSpace = sizeof(CurrentDir) - strlen(CurrentDir);

	strncat_s(CurrentDir, sizeof(CurrentDir), "plugins", FreeSpace);
	strncpy_s(PluginsFolderPath, sizeof(PluginsFolderPath), CurrentDir, strlen(CurrentDir));

	return PluginsFolderPath;
}

int ExecutePlugin(HMODULE hPlugin)
{
	DOMYJOB DoMyJob = (DOMYJOB)GetProcAddress(hPlugin, "DoMyJob");
	if(DoMyJob)
		return DoMyJob();
	else
		return FUNCADDRERR;
}

HMODULE LoadPlugin(char* PluginDllName)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE retval = INVALID_HANDLE_VALUE;
	HMODULE hModule;

	SetCurrentDirectory(GetPluginsFolder());

	retval = FindFirstFile("*.dll", &FindFileData);
	if((retval != INVALID_HANDLE_VALUE) && ((long)retval != ERROR_FILE_NOT_FOUND))
	{
		do
		{
			if(strcmp(PluginDllName, FindFileData.cFileName) == 0)
			{
				hModule = LoadLibrary(FindFileData.cFileName);
				if(hModule)
					return hModule;
			}
		}while(FindNextFile(retval, &FindFileData) != 0);
	}

	return NULL;
}

int LoadPlugins(char * PluginsFolder)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE retval;
	int cont = 0;
	HMODULE hModule;

	SetCurrentDirectory(PluginsFolder);

	retval = FindFirstFile("*.dll", &FindFileData);
	if((retval != INVALID_HANDLE_VALUE) && ((long)retval != ERROR_FILE_NOT_FOUND))
	{
		do
		{
			hModule = LoadLibrary(FindFileData.cFileName);
			if(hModule)
				PluginArray[cont++] = hModule;
		}while(FindNextFile(retval, &FindFileData) != 0);
	}
	
	return cont;
}

char* CallGetPluginName(HMODULE hPlugin)
{
	GETPLUGINNAME GetPluginName = (GETPLUGINNAME)GetProcAddress(hPlugin, "GetPluginName");
	if(GetPluginName)
		return GetPluginName();
		//printf("Plugin name: %s\n", GetPluginName());
	else
		return ("[!] Can\'t call the GetPluginName function\n");
}

char* CallGetPluginDescription(HMODULE hPlugin)
{
	GETPLUGINDESCRIPTION GetPluginDescription = (GETPLUGINDESCRIPTION)GetProcAddress(hPlugin, "GetPluginDescription");
	if(GetPluginDescription)
		return GetPluginDescription();
	else
		return ("[!] Can\'t call the GetPluginDescription function\n");
}
