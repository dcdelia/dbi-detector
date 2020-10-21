#include <windows.h>
#include "ntdll.h"

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);

char text[0x1000] = {0};

int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	NTSTATUS ntStat;
	BOOLEAN check = FALSE;

	//invalid parameter
	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(ULONG));
	if (ntStat >= 0) //it must fail
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected 1!\n");
	}

	//invalid handle
	ntStat = NtSetInformationThread((HANDLE)0xFFFFF, ThreadHideFromDebugger, 0, 0);
	if (ntStat >= 0) //it must fail
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected 2!\n");
	}

	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, 0, 0);

	if (ntStat >= 0)
	{
		//only available >= VISTA
		ntStat = NtQueryInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(BOOLEAN), 0);
		if (ntStat >= 0)
		{
			if (!check)
			{
				ShowMessageBox("Anti-Anti-Debug Tool detected 3!\n");
			}
			else
			{
				ShowMessageBox("Everything ok!\n");
			}
		}
		else
		{
			ShowMessageBox("Query ThreadHideFromDebugger not available!\n");
		}
	}
	else
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected 4!\n");
	}


	return 0;
}

void ShowMessageBox(const char * format, ...)
{
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	MessageBoxA(0, text, "Text", 0);
}