// ExecuteUnmap4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "excpt.h"

char *buffer;

int _tmain(int argc, _TCHAR* argv[])
{
	buffer = (char *) VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_READWRITE);
	uintptr_t Start, End;

	_asm {
			mov Start, offset start
			mov End, offset end
			jmp end
	}

	_asm {
start:
		nop
		ret
end:
	}

	memcpy(buffer, (void *) Start, End - Start);

	DWORD  oldProt;
	VirtualProtect(buffer, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProt);

	bool pass = true;
	__try {
		_asm {
			call dword ptr [buffer]
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		if (GetExceptionCode() == EXCEPTION_GUARD_PAGE)
			pass = true;
	}

	if (!pass) {
		printf("emulated\n");
		return 1;
	}

	printf("native\n");
	return 0;
}


