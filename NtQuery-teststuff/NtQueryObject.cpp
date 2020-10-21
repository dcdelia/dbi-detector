#include <windows.h>
#include "ntdll.h"

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);
char text[0x1000] = {0};

BYTE memory[0x1000] = {0};

int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	HANDLE debugObject;
	OBJECT_ATTRIBUTES oa;
	
	InitializeObjectAttributes(&oa,0,0,0,0);

	if (NtCreateDebugObject(&debugObject, DEBUG_ALL_ACCESS, &oa, 0) >= 0)
	{

		POBJECT_TYPE_INFORMATION objectType = (POBJECT_TYPE_INFORMATION)memory;
		if (NtQueryObject(debugObject, ObjectTypeInformation, objectType, sizeof(memory), 0) >= 0)
		{
			if (objectType->TotalNumberOfObjects == 1) //there must be 1 object...
			{
				ShowMessageBox("Everything is ok!");
			}
			else if (objectType->TotalNumberOfObjects == 0) //bad
			{
				ShowMessageBox("Anti-Anti-Debug Tool detected!");
			}
			else
			{
				ShowMessageBox("Debugger detected!\r\n\r\nTotalNumberOfHandles %d\r\nTotalNumberOfObjects %d\r\n", objectType->TotalNumberOfHandles, objectType->TotalNumberOfObjects);
			}
			
		}
		else
		{
			ShowMessageBox("NtQueryObject ObjectTypeInformation failed");
		}
		NtClose(debugObject);
	}
	else
	{
		ShowMessageBox("NtCreateDebugObject failed");
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