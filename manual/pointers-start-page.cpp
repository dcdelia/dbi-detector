#include <windows.h>
#include <stdio.h>

#define DETECTED 1
#define NOTDETECTED 0
#define PLUGINERROR -1
#define PLATFORMNOTSUPPORTED 2

#define MAX_ALLOWED 10


int SearchNtdllPtrs()
{
	int i;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBytes;
	DWORD MyAddress = 0;
	char* FuncNames[] = {"LdrLoadDll", "LdrGetProcedureAddress", "ZwSignalAndWaitForSingleObject", "ZwClose"};
	DWORD Addrs[sizeof(FuncNames)/sizeof(FuncNames[0])];
	DWORD* MyPtr;
	int cant;

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    printf("Base of ntdll: %p\n", hNtdll);
	for(i=0; i < sizeof(FuncNames)/sizeof(FuncNames[0]); i++) {
		Addrs[i] = (DWORD)GetProcAddress(hNtdll, FuncNames[i]);
		printf("Function at %p: %s\n", Addrs[i], FuncNames[i]);
	}

	do
	{
		numBytes = VirtualQuery((LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if(mbi.State == MEM_COMMIT)
		{
			MyPtr = (DWORD*)mbi.BaseAddress;
			printf("@%p", (void*)mbi.BaseAddress);

			cant = 0;
            //printf("Elements:");
			for(i=0; i <  sizeof(FuncNames)/sizeof(FuncNames[0]); i++)
			{
				if((DWORD)Addrs[i] == *MyPtr)
					cant++;
				printf("\t%x", *MyPtr);

				MyPtr++;
			}
            printf("\n");

			if(cant == sizeof(FuncNames)/sizeof(FuncNames[0]))
				return DETECTED;
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return NOTDETECTED;
}

int main()
{
	printf("Detected: %d\n", SearchNtdllPtrs());
    system("pause");
    return 0;
}

