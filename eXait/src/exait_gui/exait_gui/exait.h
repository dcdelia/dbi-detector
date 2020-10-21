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

#include "exait_hdrs.h"

#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

BOOL CALLBACK AppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch(uMsg)
  {
  case WM_INITDIALOG:

   InitControlsEx();

   SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(hGlobalInstance, MAKEINTRESOURCE(XICON)));
   SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hGlobalInstance, MAKEINTRESOURCE(XICON)));

   hList = GetDlgItem(hDlg, LV_PLUGINLIST);
   if(hList)
   {
		ListView_SetExtendedListViewStyle(hList, LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP | LVS_EX_LABELTIP);

		CreateColumns(hList);
		PopulateListView(hList, LoadPlugins(GetPluginsFolder()));
   }

   return 1;

  case WM_NOTIFY:
	  {
		  LPNMHDR lpnm = (LPNMHDR) lParam;
		  switch (lpnm->code)
		  {
				case LVN_GETINFOTIP:
					{
						LPNMLVGETINFOTIP pGetInfoTip = (LPNMLVGETINFOTIP)lParam;

							if (pGetInfoTip != NULL)
							{
								g_szToolTip[0] = '\0';
								StringCchPrintf(
									g_szToolTip,
									ARRAYSIZE(g_szToolTip),
									"%s",
									"Tooltip");

								pGetInfoTip->pszText = g_szToolTip;
							}
					}
					break;
				
				default: 
					break;
		  }
	  }
	  return 0;

  case WM_COMMAND:
    switch(wParam)
    {
    case IDOK:
		ExecuteSelectedPlugins(hList);
      return 0;
	case IDCLEAR:
		ClearStatusAndResultRows(hList);
		return 0;
    case BT_ABOUT:
	    ShowAboutInformation(hDlg);
        return 0; 
	case IDREFRESH:
		ListView_DeleteAllItems(hList);
		PopulateListView(hList, LoadPlugins(GetPluginsFolder()));

		if(IsDlgButtonChecked(hDlg, CHECKALL) == BST_CHECKED)
			CheckButtons(hList);

		return 0;
	case CHECKALL:
		ChangeStatus(hDlg, hList);
		return 0;
	case IDCANCEL:
		if(MessageBox(hDlg, TEXT("Are you sure you want to quit?"), TEXT("Exit?"), MB_YESNO) == IDYES)
			EndDialog(hDlg, 0);
    }
  }
  return 0;
}

void CheckButtons(HWND hList)
{
	int item, iCount;
	
	iCount = ListView_GetItemCount(hList);
	for(item = 0; item < iCount; item++)
		ListView_SetCheckState(hList, item, TRUE);

}

void UncheckButtons(HWND hList)
{
	int item, iCount;

	iCount = ListView_GetItemCount(hList);
	for(item = 0; item < iCount; item++)
		ListView_SetCheckState(hList, item, FALSE);
}

void ChangeStatus(HWND hDlg, HWND MyhList)
{
	if(IsDlgButtonChecked(hDlg, CHECKALL) == BST_CHECKED)
		CheckButtons(MyhList);
	else if(IsDlgButtonChecked(hDlg, CHECKALL) == BST_UNCHECKED)
		UncheckButtons(MyhList);
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

void UnloadPlugins(int cont)
{
	int i;

	for(i = 0; i < cont; i++)
		FreeLibrary(PluginArray[i]);
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

char* MyGetPluginName(HMODULE hPlugin)
{
	static char Error[] = "Fucking error!";

	GETPLUGINNAME GetPluginName = (GETPLUGINNAME)GetProcAddress(hPlugin, "GetPluginName");
	if(GetPluginName)
	{
		return GetPluginName();
	}
	else
		MessageBox(NULL, "[!] Can\'t call the GetPluginName function", "Ups!", MB_ICONERROR);
	return Error;
}

char* MyGetPluginDescription(HMODULE hPlugin)
{
	static char Error[] = "Fucking error!";

	GETPLUGINDESCRIPTION GetPluginDescription = (GETPLUGINDESCRIPTION)GetProcAddress(hPlugin, "GetPluginDescription");
	if(GetPluginDescription)
	{
		return GetPluginDescription();
	}
	else
		MessageBox(NULL, "[!] Can\'t call the GetPluginDescription function", "Ups!", MB_ICONERROR);
	return Error;
}

void ShowAboutInformation(HWND hDlg)
{
	MessageBox(hDlg, "eXtensible Anti-Instrumentation Tester\n\nCoded by:\n\tFrancisco Falcon (@fdfalcon)\n\tNahuel C. Riva (@crackinglandia)\n\nBuenos Aires, Argentina",
	"eXait v1.0", 
	MB_ICONINFORMATION);
}

HWND GetWindowOwner(HWND MyHandle)
{
	return GetWindow(MyHandle, GW_OWNER);
}

BOOL MySetItem(HWND MyhList, int MyItem, int MySubItem, char* MyText)
{
	LVITEM lvItem;

	memset(&lvItem, 0, sizeof(lvItem));

	lvItem.mask = LVIF_TEXT;
	lvItem.cchTextMax = MAX_PATH;

	lvItem.iItem = MyItem;
	lvItem.iSubItem = MySubItem;

	lvItem.pszText = TEXT(MyText);

	if(!ListView_SetItem(MyhList, &lvItem))
		return FALSE;
	return TRUE;
}

void InitPluginNameRow(HWND MyhList, int row)
{
	int count;

	for(count = 1; count < MAX_COLS; count++)
	{
		if(!MySetItem(MyhList, row, 1, MyGetPluginName(PluginArray[row])))
			MessageBox(GetWindowOwner(MyhList), TEXT("Couldn't insert SubItem"), TEXT("Ups!"), MB_ICONERROR);
	}
}

void InitPluginDescriptionRow(HWND MyhList, int row)
{
	int count;
	for(count = 1; count < MAX_COLS; count++)
	{
		if(!MySetItem(MyhList, row, 4, MyGetPluginDescription(PluginArray[row])))
			MessageBox(GetWindowOwner(MyhList), TEXT("Couldn't insert SubItem"), TEXT("Ups!"), MB_ICONERROR);
	}
}

void InitResultRow(HWND MyhList, int row)
{
	int count;
	for(count = 1; count < MAX_COLS; count++)
	{
		if(!MySetItem(MyhList, row, 3, "NaN"))
			MessageBox(GetWindowOwner(MyhList), TEXT("Couldn't insert SubItem"), TEXT("Ups!"), MB_ICONERROR);
	}
}

void InitStatusRow(HWND MyhList, int row)
{
	int count;
	for(count = 1; count < MAX_COLS; count++)
	{
		if(!MySetItem(MyhList, row, 2, "NaN"))
			MessageBox(GetWindowOwner(MyhList), TEXT("Couldn't insert SubItem"), TEXT("Ups!"), MB_ICONERROR);
	}
}

void ClearStatusAndResultRows(HWND MyhList)
{
	int row, maxRows;

	maxRows = ListView_GetItemCount(MyhList);
	for(row = 0; row < maxRows; row++)
	{
		InitStatusRow(MyhList, row);
		InitResultRow(MyhList, row);
	}
}

void CreateColumns(HWND MyhList)
{
	LVCOLUMN lvCol = {0};
	int index;
	char buffer[MAX_PATH];
	char* colTitles[] = {"Enable", "Plugin name", "Result", "Status", "Plugin description"};

	for(index = 0; index < MAX_COLS; index++)
	{
		memset(&lvCol, 0, sizeof(lvCol));

		if ((index == 0) || (index == 2) || (index == 3))
		{
			lvCol.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_IDEALWIDTH;
			lvCol.fmt = LVCFMT_CENTER;
		}
		else
			lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;

		lvCol.pszText = colTitles[index];
		lvCol.cchTextMax = strlen(colTitles[index]);
		lvCol.cx = lvCol.cxIdeal = 100;

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(buffer, sizeof(buffer), "Couldn't insert column %d", index);
			MessageBox(GetWindowOwner(MyhList), buffer, TEXT("Ups!"), MB_ICONERROR);
		}
		else
		{
			ListView_SetColumnWidth(MyhList, 0, 50);
			ListView_SetColumnWidth(MyhList, 1, 250);
			ListView_SetColumnWidth(MyhList, 2, 50);
			ListView_SetColumnWidth(MyhList, 3, 50);
			ListView_SetColumnWidth(MyhList, 4, 400);
		}
	}

}

void InitControlsEx(void)
{
   INITCOMMONCONTROLSEX icex;
   icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
   icex.dwICC = ICC_LISTVIEW_CLASSES;
   InitCommonControlsEx(&icex);
}

void PopulateListView(HWND MyhList, int CantPlugins)
{
	LVITEM lvItem;
	int index;

	for(index = 0; index < CantPlugins; index++)
	{
		memset(&lvItem, 0, sizeof(lvItem));

		lvItem.iItem = index;
		lvItem.iSubItem = 0;
		
		if(ListView_InsertItem(MyhList, &lvItem) != -1)
		{
			InitPluginNameRow(MyhList, index);
			InitPluginDescriptionRow(MyhList, index);
			InitResultRow(MyhList, index);
			InitStatusRow(MyhList, index);
		}
		else
			MessageBox(GetWindowOwner(MyhList), TEXT("Couldn't insert Item"), TEXT("Ups!"), MB_ICONERROR);
	}
}

void ExecuteSelectedPlugins(HWND MyhList)
{
	int retval, index, cant = ListView_GetItemCount(MyhList);

	if(cant)
	{
		for(index = 0; index < cant; index++)
		{
			if(ListView_GetCheckState(MyhList, index))
			{
				retval = ExecutePlugin(PluginArray[index]);

				switch(retval)
				{
					case DETECTED:
						MySetItem(MyhList, index, 2, "Positive");
						break;
					case NOTDETECTED:
						MySetItem(MyhList, index, 2, "Negative");
						break;
					case PLUGINERROR:
						MySetItem(MyhList, index, 2, "Plugin Error");
						break;
					case PLATFORMNOTSUPPORTED:
						MySetItem(MyhList, index, 2, "Platform not supported");
						break;
					default: 
						MySetItem(MyhList, index, 2, "Unknown Result");
						break;
				}					

				MySetItem(MyhList, index, 3, "Terminated");
			}
		}
		
		//UnloadPlugins(retval);
	}
}