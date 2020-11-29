#include <windows.h>
#include <stdio.h>

#define SAVED_HANDLES   1024
#define TRY_MAX         17000000
#define CTR_TICK        250000

int main() {
	HANDLE hProcPseudo = GetCurrentProcess();
	LPHANDLE *list = (LPHANDLE*)malloc(sizeof(LPHANDLE) * SAVED_HANDLES);
	memset(list, 0, sizeof(list));
	//Then call either:
	HANDLE lpRealHandle = CreateEvent(NULL, FALSE, FALSE, NULL);
	int i = 0;

	for (i = 0; i < TRY_MAX; i++) {
        if (i && i%CTR_TICK == 0) { printf("x"); fflush(0); }
		BOOL ret = DuplicateHandle(hProcPseudo,
                lpRealHandle,
                hProcPseudo,
                (void**)&list[i%SAVED_HANDLES],
                DUPLICATE_SAME_ACCESS,
                0,
                0);
		if (ret==0) {
            printf("\nError code: %d\n", GetLastError());
            break;
        }
	}

    printf("\nEnded with: %d\n", i);

    return 0;
}