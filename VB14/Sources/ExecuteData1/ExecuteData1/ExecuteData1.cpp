// ExecuteData1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"


int _tmain(int argc, _TCHAR* argv[])
{
	char *buffer = (char *) VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_READWRITE);
	*buffer = 0xc3;

	__try {
		_asm call buffer
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
			printf("native\n");
			return 0;
		}
	}

	printf("emulated\n");
	return 1;
}

