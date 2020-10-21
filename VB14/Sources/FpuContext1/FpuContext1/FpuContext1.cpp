// FpuContext1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdint.h>
#include <stdio.h>

uint32_t fpu_save_area[7];

int _tmain(int argc, _TCHAR* argv[])
{
	printf("Verifying that the EIP leaked by FNSTENV is properly virtualized.\n");

	unsigned int Start;

	_asm {
Start:
		fsin
		fnstenv fpu_save_area
		lea eax, start
		mov Start, eax
	}

	printf("* Guest EIP: %x\n", Start);
	printf("* Leaked EIP: %x\n", fpu_save_area[3]);

	if (fpu_save_area[3] == Start) {
		printf("Test passed.\n");
		return 0;
	}

	printf("Test failed.\n");
	return 1;
}

