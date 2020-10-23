//http://waleedassar.blogspot.com (@waleedassar)
//Simple code that shows how the "ReadProcessMemory" function can be used to defeat memory breakpoints(whether PAGE_GUARD or PAGE_NOACCESS).
 
//#include "stdafx.h"
#include "windows.h"
#pragma comment(lib,"ntdll")
#pragma comment(lib,"user32")
#define MemoryBasicVlmInformation 0x3
struct MEMORY_BASIC_VLM_INFORMATION
{
        unsigned long ImageBase;
        unsigned long blah[0x2];
        unsigned long SizeOfImage;
};
 
extern "C"
{
        int __stdcall ZwQueryVirtualMemory(HANDLE,void*,int,void*,int,unsigned long*);
}
 
int main(int argc, char* argv[])
{
        unsigned long out=0;
    MEMORY_BASIC_VLM_INFORMATION MBVI={0};
    unsigned long IB=(unsigned long)GetModuleHandle(0);
    ZwQueryVirtualMemory(GetCurrentProcess(),(void*)IB,MemoryBasicVlmInformation,&MBVI,sizeof(MBVI),&out);
    unsigned long SizeOfImage=MBVI.SizeOfImage;
    char* p=(char*)VirtualAlloc(0,SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
        //Setting a memory BP any where in the memory image will cause ReadProcessMemory to fail.
    if(ReadProcessMemory((void*)0xFFFFFFFF,(void*)IB,p,SizeOfImage,0))
    {
             MessageBox(0,"Expected behavior","waliedassar",0);
    }
    else
    {
             MessageBox(0,"Memory BP(s) detected","waliedassar",0);
    }
    return 0;
}
