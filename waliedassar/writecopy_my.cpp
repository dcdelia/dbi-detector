//http://waleedassar.blogspot.com (@waleedassar)
//#include "stdafx.h"

// NOTE: use MSVC and/or make sure that section xyz is RWX
#include "windows.h"
#pragma comment(linker,"/incremental:no")
#pragma comment(linker,"/entry:main")
//#pragma comment(lib,"ntdll")
#pragma comment(lib,"kernel32")
#pragma comment(lib,"user32")
#define ProcessDebugPort 0x7
#define ProcessDebugObjectHandle 0x1E
#define ProcessDebugFlags 0x1F
 
/*extern "C"
{
    int __stdcall ZwQueryInformationProcess(HANDLE,int,void*,unsigned long,unsigned long*);
}*/
 
 
 
//If PE section has Read-Write-Execute access attributes, then its memory pages are initially PAGE_EXECUTE_WRITECOPY and any
//attempt to write to it e.g. Placing an software breakpoint or Stepping Over changes it to PAGE_EXECUTE_READWRITE. 
#pragma comment(linker,"/SECTION:xyz,ERW") 
#pragma code_seg("xyz")
int main2()
{
    //-----------------Stuff file with some anti-debug tricks-------------------
    unsigned long _port_=0;
    /*ZwQueryInformationProcess(GetCurrentProcess(),ProcessDebugPort,&_port_,0x4,0);
    if(_port_)
    {
                MessageBoxW(0,L"BeingDebugged for ProcessDebugPort",L"waliedassar",0);
                ExitProcess(-1);
    }*/
    /*unsigned long DbgObjHand=0;
    int ret=ZwQueryInformationProcess(GetCurrentProcess(),ProcessDebugObjectHandle,&DbgObjHand,0x4,0);
    if(ret>=0 || DbgObjHand)
    {
                MessageBox(0,L"BeingDebugged",L"waliedassar",0);
                ExitProcess(-2);
    }
    unsigned long DbgFlags=0;
    ZwQueryInformationProcess(GetCurrentProcess(),ProcessDebugFlags,&DbgFlags,0x4,0);
    if(DbgFlags==0)
    {
                MessageBox(0,L"BeingDebugged",L"waliedassar",0);
                ExitProcess(-2);
    }*/
    //-------------------------------------------------------------------------
    void* base=(void*)&main2;//????
 
    MEMORY_BASIC_INFORMATION MBI={0};
    VirtualQuery(base,&MBI,sizeof(MBI));
    if(MBI.Protect!=PAGE_EXECUTE_WRITECOPY)
    {
             MessageBoxW(0,L"BeingDebugged for WriteCopy",L"waliedassar",0);
             ExitProcess(-2);
    }
    MessageBoxW(0,L"All good!",L"waliedassar",0);
    return 0;
}
#pragma code_seg()
 
int main(int argc, char* argv[])
{
    main2();
    return 0;
}
