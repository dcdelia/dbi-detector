// ebxcatch.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
#include <windows.h>

unsigned char* data = NULL;
unsigned char* orgcode = NULL;
unsigned char* codecach = NULL;
int cflag = 0;

extern "C" void WriteEscape(unsigned char* addr);

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {

	return EXCEPTION_EXECUTE_HANDLER;

}

void dummy_func()
{
	printf("Dummy func executed!\n");
	return;
}

void escape1()
{	
	void (*fpt)();
	fpt = dummy_func;

	printf("escaped!\n");

	if (cflag == 2)
	{
		
		for (int i = 0; i < 100; i++)
		{
			__asm{
				call fpt
			}
		}

		printf("extra 100 dummy_func executed while escape\n");
	}
	
	return;

}


void test()
{
	//unsigned char* callback = 0;

	__asm{
		nop
		nop
		push eax
		pop eax
		nop
		nop
		push eax
		pop eax
		nop
		nop
		push eax
		pop eax
		nop
		nop
		jmp print1
		nop
		nop
		nop
		nop
		nop
		call escape1
		ret
	}

	//printf("ebx value is 0x%x\n", callback);
print1:	printf("test called\n");
	return;
}





int _tmain(int argc, _TCHAR* argv[])
{	
	//for (int i = 0; i<3; i++)
		//printf("[%d]:\t0x%x\n", i, TlsGetValue(i));

	int i;
	int j;
	int sig_count = 0;

	void(*fpt)();
	fpt = dummy_func;

	test();

	i = (int)test;
	data = (unsigned char*)i;

	
	for (int i = 0; i<0x10000; i++)
	{
		data = (unsigned char*)(i * 0x1000);

		__try{
			if (data[0] == 0x4d)
				printf("sig: 0x%x\n", data);
		}
		__except (filter(GetExceptionCode(), GetExceptionInformation())){
			continue;
		}


		for (int j = 0; j<0xfff; j++)
		{
			data = (unsigned char*)(i * 0x1000 + j);
			__try{
				if (data[0] == 0x90 &&
					data[1] == 0x90 &&
					data[2] == 0x50 &&
					data[3] == 0x58)
				{
					
					printf("signature: 0x%x\n", data);
					sig_count++;

					if (sig_count == 1)
						orgcode = data;

					if (sig_count == 2)
						codecach = data;

					break;
				}
			}
			__except (filter(GetExceptionCode(), GetExceptionInformation())){

			}
		}

	}

	//printf("orginal code: 0x%x\n", orgcode);
	//printf("codecach code: 0x%x\n", codecach);
	printf("mem search completed, signature count:%d\n", sig_count);
	printf("argc = %d\n", argc);
	cflag = argc;

	if (cflag == 3)
	{	
			for (int i = 0; i < 100; i++)
			{
				__asm{
					call fpt
				}
			}

			printf("extra 100 dummy_func executed under Pin\n");
	}

	if (sig_count==2)
	{
		printf("Running under DBI!\n");
		
		__asm{
			push eax
			push ebx

			mov eax, orgcode		
			mov ebx, codecach

			add eax, 0x12
			sub eax, ebx
			sub eax, 5

			mov byte ptr [ebx], 0xe8
			add ebx, 1
			mov dword ptr [ebx], eax
			
			pop ebx
			pop eax
		}
	}


	//WriteEscape(data);

	
	getchar();
	test();


	return 0;
}

