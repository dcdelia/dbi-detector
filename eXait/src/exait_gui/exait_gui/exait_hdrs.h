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

#include <windows.h>
#include <Commctrl.h>
#include <stdio.h>
#include <Strsafe.h>

#include "stdafx.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")

// constants definition
#define MAX_PLUGINS 1024
#define FUNCADDRERR -2
#define MAX_COLS 5

// function prototypes
void InitControlsEx(void);
void CheckButtons(HWND hList);
void UncheckButtons(HWND hList);
void ChangeStatus(HWND hDlg, HWND hList);
void ExecuteSelectedPlugins(HWND MyhList);
void PopulateListView(HWND MyhList, int CantPlugins);
void InitStatusRow(HWND MyhList, int row);
void InitResultRow(HWND MyhList, int row);
void InitPluginDescriptionRow(HWND MyhList, int row);
void InitPluginNameRow(HWND MyhList, int row);
void CreateColumns(HWND MyhList);
void ClearStatusAndResultRows(HWND MyhList);
void ShowAboutInformation(HWND);
void UnloadPlugins(int);

HWND GetWindowOwner(HWND MyHandle);

BOOL MySetItem(HWND MyhList, int MyItem, int MySubItem, char* MyText);
BOOL CALLBACK AppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

int LoadPlugins(char *PluginsPath);
int ExecutePlugin(HANDLE hPlugin);

char* GetPluginsFolder(void);
char* MyGetPluginName(HMODULE hPlugin, HWND hList, int iItem);
char* MyGetPluginDescription(HMODULE hPlugin, HWND hList, int iItem);

typedef int (__stdcall *DOMYJOB)(void);
typedef char* (__stdcall *GETPLUGINNAME)(void);
typedef char* (__stdcall *GETPLUGINDESCRIPTION)(void);

// global variables
HMODULE PluginArray[MAX_PLUGINS] = {(HMODULE)-1};
HWND hList = NULL;
HINSTANCE hGlobalInstance;
char g_szToolTip[100] = {0};
