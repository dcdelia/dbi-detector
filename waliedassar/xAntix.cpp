//#include "stdafx.h"
#include "windows.h"
#include "stdio.h"


typedef union _PSAPI_WORKING_SET_BLOCK {
  unsigned long Flags;
  struct {
    unsigned long Protection  :5;
    unsigned long ShareCount  :3;
    unsigned long Shared  :1;
    unsigned long Reserved  :3;
    unsigned long VirtualPage  :20;
  };
}PSAPI_WORKING_SET_BLOCK, *PPSAPI_WORKING_SET_BLOCK;


typedef struct _PSAPI_WORKING_SET_INFORMATION {
  unsigned long               NumberOfEntries;
  PSAPI_WORKING_SET_BLOCK WorkingSetInfo[1];
} PSAPI_WORKING_SET_INFORMATION, *PPSAPI_WORKING_SET_INFORMATION;


/*
extern "C"
{
	BOOL __stdcall QueryWorkingSet(HANDLE hProcess,void* pv,unsigned long cb);
}
*/


typedef BOOL(__stdcall *QWS)(HANDLE hProcess,void* pv,unsigned long cb);


unsigned long GetCurrentEIP()
{
	unsigned long x_eip=0;
	__asm
	{
		call x
x:
		pop eax
		mov x_eip,eax
	}
	return x_eip;
}


int main(int argc, char* argv[])
{

	QWS QueryWorkingSet = (QWS)GetProcAddress(GetModuleHandle("kernel32.dll"),"K32QueryWorkingSet");
	if(!QueryWorkingSet)
	{
		printf("Can't resolve address\r\n");
		return 0;
	}


	PSAPI_WORKING_SET_INFORMATION* pWSI = (PSAPI_WORKING_SET_INFORMATION*)VirtualAlloc(0,0x10000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
	if(!pWSI) return 0;

	BOOL ret = QueryWorkingSet(GetCurrentProcess(),pWSI,0x10000);
	if(!ret)
	{
		VirtualFree(pWSI,0,MEM_RELEASE);
		return 0;
	}

	unsigned long Num = pWSI->NumberOfEntries;
	if(!Num)
	{
		VirtualFree(pWSI,0,MEM_RELEASE);
		return 0;
	}

	printf("--------------\r\n");

	bool debugger_present = false;

	for(unsigned long i=0;i<Num;i++)
	{
		unsigned long Addr= ((pWSI->WorkingSetInfo[i].VirtualPage))<<0x0C;
		printf("%x\r\n",Addr);
		if(Addr==(GetCurrentEIP()&0xFFFFF000))
		{
			//printf("Page found\r\n");
			printf("Shared %s\r\n",(pWSI->WorkingSetInfo[i].Shared)?"true":"false");
			printf("ShareCount: %x\r\n",pWSI->WorkingSetInfo[i].ShareCount);
			if( (pWSI->WorkingSetInfo[i].Shared==0) || (pWSI->WorkingSetInfo[i].ShareCount==0) )
			{
				debugger_present = true;
				break;
			}
		}
	}

	if(debugger_present) printf("Debugger present\r\n");
	else                 printf("No debugger\r\n");

	return 1;
}
