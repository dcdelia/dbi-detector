// TransientException2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "excpt.h"

#define PAGE_SIZE 4096

char *buffer;
int cnt = 0;

int _tmain(int argc, _TCHAR* argv[])
{
	printf("Verifying that a PAGE_GUARD protection is consumed from all blocks.\n");

	buffer = (char *) VirtualAlloc(NULL, 2 * PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("* Allocated two PAGE_EXECUTE_READWRITE pages at %p.\n", buffer);

	uintptr_t Start, PageBreak, End;
	
	_asm {
			mov Start, offset start
			mov PageBreak, offset pb
			mov End, offset end
			jmp end
	}

	_asm {
start:
			cmp cnt, 0
			jz pb
			nop
pb:
			nop
			inc cnt
			ret
end:
	}

	uintptr_t dest = (uintptr_t) buffer + PAGE_SIZE - (PageBreak - Start);

	printf("* Placing test code around the page boundary %p - %p.\n", (void *) dest, (void *) (dest + (End - Start)));
	
	memcpy((void *) dest, (void *) Start, End - Start);

	printf("* Adding PAGE_GUARD protection to page %p.\n", (void *) (buffer + PAGE_SIZE));
	DWORD  oldProt;
	VirtualProtect(buffer + PAGE_SIZE, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProt);

	bool pass = false;
	__try {
		printf("* Executing test code (first round).\n");
		_asm {
			call dword ptr [dest]
		}
		printf("* Test code executed.\n");
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		printf("* Got exception %x.\n", GetExceptionCode());
		if (GetExceptionCode() == EXCEPTION_GUARD_PAGE)
			pass = true;
	}

	if (!pass) {
		printf("Test failed.\n");
		return 1;
	}

	__try {
		printf("* Executing test code (second round).\n");
		_asm {
			call dword ptr [dest]
		}
		printf("* Test code executed.\n");
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		printf("* Got exception %x.\n", GetExceptionCode());
		pass = false;
		
	}

	if (!pass) {
		printf("Test failed.\n");
		return 2;
	}

	printf("Test passed.\n");
	return 0;
}

