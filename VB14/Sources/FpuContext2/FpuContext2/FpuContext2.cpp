// FpuContext2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdint.h>
#include <stdio.h>

uint16_t fpu_save_area[7];

int _tmain(int argc, _TCHAR* argv[])
{
	printf("Verifying that the IP leaked by 0x66 FNSTENV is properly virtualized.\n");

	unsigned short Start;

	_asm {
start:
		fsin
		_emit 0x66
		fnstenv fpu_save_area
		lea eax, start
		mov word ptr Start, ax
	}

	printf("* Guest IP: %x\n", Start);
	printf("* Leaked IP: %x\n", fpu_save_area[3]);

	if (fpu_save_area[3] == Start) {
		printf("Test passed.\n");
		return 0;
	}

	printf("Test failed.\n");
	return 1;
}
