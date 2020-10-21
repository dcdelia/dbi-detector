#include <windows.h>
#include "ntdll.h"

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);
void WINAPI ContinueExecution(LPVOID lpFlsData);
char text[0x1000] = {0};


typedef struct _RTL_UNKNOWN_FLS_DATA {
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID Argument;
} RTL_UNKNOWN_FLS_DATA,*PRTL_UNKNOWN_FLS_DATA;

typedef struct _FLS_CALLBACK {
	PVOID Unknown;
	PVOID StartAddress;
} FLS_CALLBACK, *PFLS_CALLBACK;

#define UNKNOWN_MAX_CALLBACKS 5

typedef struct _FLS_CALLBACK_INFO
{
	PVOID Unknown;
	FLS_CALLBACK Callbacks[UNKNOWN_MAX_CALLBACKS];
} FLS_CALLBACK_INFO, *PFLS_CALLBACK_INFO;

FLS_CALLBACK_INFO info = { 0 };
RTL_UNKNOWN_FLS_DATA rtl = {0};

BYTE UnknownReturnBuffer[100] = {0};

ULONG backupFlsNumberOfCallbacks = 0;
DWORD_PTR backupFlsCallback = 0;

ULONG * pFlsNumberOfCallbacks = 0;
DWORD_PTR * pFlsCallbackInfo = 0;

int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	info.Callbacks[0].StartAddress = ContinueExecution;

	rtl.unk1 = UnknownReturnBuffer;
	rtl.unk2 = UnknownReturnBuffer;
	rtl.unk3 = UnknownReturnBuffer;
	rtl.Argument = (LPVOID)0x1337;

	DWORD_PTR pPeb = 0;
#ifdef _WIN64
#define PEB_FLS_CALLBACK_OFFSET 0x0320
#define PEB_FLS_NUMBERCALLBACKS_OFFSET 0x0350
	pPeb = (DWORD_PTR)__readgsqword(12 * sizeof(DWORD_PTR)); //PEB Address
#else
#define PEB_FLS_CALLBACK_OFFSET 0x020C
#define PEB_FLS_NUMBERCALLBACKS_OFFSET 0x022C
	pPeb = (DWORD_PTR)__readfsdword(12 * sizeof(DWORD_PTR)); //PEB Address
#endif

	pFlsNumberOfCallbacks = (ULONG *)(pPeb + PEB_FLS_NUMBERCALLBACKS_OFFSET);
	pFlsCallbackInfo = (DWORD_PTR *)(pPeb + PEB_FLS_CALLBACK_OFFSET);

	//backup
	backupFlsNumberOfCallbacks = *pFlsNumberOfCallbacks;
	backupFlsCallback = *pFlsCallbackInfo;

	//we have only 1 callback in the struct
	*pFlsCallbackInfo = (DWORD_PTR)&info;
	*pFlsNumberOfCallbacks = 1;

	RtlProcessFlsData(&rtl);
	
	//restore everything like nothing happened
	*pFlsCallbackInfo = backupFlsCallback;
	*pFlsNumberOfCallbacks = backupFlsNumberOfCallbacks;


	return 0;
}

void WINAPI ContinueExecution(LPVOID lpFlsData)
{
	ShowMessageBox("This thread runs, param %p!", lpFlsData);
}

void ShowMessageBox(const char * format, ...)
{
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	MessageBoxA(0, text, "Text", 0);
}