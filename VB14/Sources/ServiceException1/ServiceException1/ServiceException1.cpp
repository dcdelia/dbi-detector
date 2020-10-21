// ServiceException1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include <stdio.h>
#define PATTERNSIZE 0x200
int _tmain(int argc, _TCHAR* argv[])
{
	
	printf("Verifying that a pattern left on the stack is not smashed by SMC.");

	DWORD  oldProt;
	VirtualProtect(_tmain, 8192, PAGE_EXECUTE_READWRITE, &oldProt);
	void* firstchangeaddr = NULL;
	printf("ciao0\n");
	unsigned char* bufferptr = (unsigned char*)VirtualAlloc(NULL, PATTERNSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("ciao1\n");
	_asm {
		

	    mov edi,esp
		sub edi, PATTERNSIZE
		mov ecx, PATTERNSIZE
		mov eax, 65
		
		rep stosb
		
		mov byte ptr smc, 0x90

smc:
		_emit 0xcc
		

		mov esi, esp
		mov edi, bufferptr;
		sub esi, PATTERNSIZE
		mov ecx, PATTERNSIZE
		rep movsb

	}
	printf("ciao2\n");
	bool passed = true;
	int idx = 0;
	for (int i= PATTERNSIZE-1; i>=0; i--) {
		
		if ((idx++ % 32)==0 )
			printf("\n [ESP-%04x]  ", (PATTERNSIZE-1) - i);

		printf("%c", bufferptr[i] != 65 ? 'X' : '.');
		
		if (bufferptr[i] != 65) {
			
			if (!firstchangeaddr)
				firstchangeaddr = &bufferptr[i];

			passed = false;
		}


	}

	printf("\n");

	printf("> Address of first difference: %p\n", firstchangeaddr);

	VirtualFree(bufferptr, PATTERNSIZE, MEM_RELEASE);

	if (passed) {
		printf("> Test passed.\n");
		return 0;
	}

	printf("> Test failed.\n");
	return 1;
}

