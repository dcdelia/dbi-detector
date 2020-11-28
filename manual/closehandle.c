// requires MSVC

#include <windows.h>
#include <stdio.h>

int main() {
    printf("Ciao caro!\n");
    __try {
		CloseHandle((HANDLE)0x99999999ULL);
	}
	__except (1) { // EXCEPTION_EXECUTE_HANDLER
		printf("Thanks, I can detect you.\n");;
	}
    return 0;
}
