//http://waleedassar.blogspot.com (@waleedassar)
//Code to bypass Memory Breakpoints (whether PAGE_GUARD or PAGE_NOACCESS)
//Depends on the fact that TEB's (or PEB's) memory protection can not be non-writable or guarded, but can still be eXecutable.
//In this case, i create a dummy thread in a suspended state and then use its TEB memory for executing code.
//Warning: never resume the thread.
//#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#pragma comment(linker,"/OPT:NOREF")
#define ThreadBasicInformation 0x0
struct THREAD_BASIC_INFORMATION
{
	unsigned long ExitStatus;
	unsigned long TEBAddress;
	unsigned long shit[0x5]; //Only to preserve the structure's size
};
extern "C"
{
	int __stdcall ZwQueryInformationThread(HANDLE,unsigned long,THREAD_BASIC_INFORMATION*,unsigned long,unsigned long*);
}
int dummy()
{
	int x=0;
	int y=x;
	return y;
}

void Shit()
{
	MessageBox(0,"Nothing interesting","waliedassar",0);
	return;
}

typedef void ktm();

int main()
{
	unsigned long tid=0;
	HANDLE hThread=CreateThread(0,0x1000,(LPTHREAD_START_ROUTINE)&dummy,0,CREATE_SUSPENDED,&tid);
	if(hThread)
	{
		THREAD_BASIC_INFORMATION TBI={0};
		if(ZwQueryInformationThread(hThread,ThreadBasicInformation,&TBI,sizeof(TBI),0)>=0)
		{
			//Make it executable
			char* p=(char*)VirtualAlloc((void*)(TBI.TEBAddress),0x1000,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
			//Destroy and never resume
			memset(p,0x90,0x1000);
			memcpy(p,(void*)&Shit,0x1000);
			/*__asm
			{
				mov eax,p
				call eax //
			}*/
			ktm* func = (ktm*)p;
			func();

			ExitProcess(0);
		}
	}
	return 0;
}
