#include <windows.h>
#include "ntdll.h"

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);
void WINAPI ContinueExecution(LPVOID param);

char text[0x1000] = {0};

#define THREAD_ALL_ACCESS_VISTA         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
	0xFFFF)


//SOURCE: http://processhacker.sourceforge.net/doc/ntpsapi_8h_source.html
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	HANDLE hThread = 0;
	NTSTATUS ntStat = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS_VISTA, 0, NtCurrentProcess, (LPTHREAD_START_ROUTINE)ContinueExecution, 0, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, 0);
	if (ntStat >= 0)
	{
		WaitForSingleObject(hThread, INFINITE);
	}
	else
	{
		ShowMessageBox("NtCreateThreadEx failed!");
	}
	return 0;
}

void WINAPI ContinueExecution(LPVOID param)
{
	BOOLEAN check = FALSE;

	ShowMessageBox("This thread is hidden from debugger!");

	if (NtQueryInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(BOOLEAN), 0) >= 0)
	{
		if (!check)
		{
			ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
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

void ShowMessageBox(const char * format, ...)
{
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	MessageBoxA(0, text, "Text", 0);
}