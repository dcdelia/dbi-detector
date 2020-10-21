#include <windows.h>
#include "ntdll.h"

#pragma comment(linker,"/ENTRY:WinMain")

DWORD WINAPI ThreadFunction(LPVOID lpThreadParameter);
void testContext();
LONG NTAPI VectorHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
void HardwareBreakpointTest();
void ExceptionContinue();


#define CURRENT_PROCESS ((HANDLE) -1)
#define CURRENT_THREAD  ((HANDLE) -2)
#define NtCurrentProcess CURRENT_PROCESS
#define NtCurrentThread CURRENT_THREAD

int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{	
    HardwareBreakpointTest();

    ExitProcess(0);
	return 0;
}


void HardwareBreakpointTest()
{
    testContext();
    AddVectoredExceptionHandler(TRUE, VectorHandler);
    *((DWORD *)0) = 0;
    MessageBoxW(0, L"Never reach me!", L"Test", 0);
}

void ExceptionContinue()
{
    HANDLE hThread = CreateRemoteThread(NtCurrentProcess,0,0,ThreadFunction,0,0,0);
    WaitForSingleObject(hThread, INFINITE);
    ExitProcess(0);
}

DWORD WINAPI ThreadFunction(LPVOID lpThreadParameter)
{
    MessageBoxW(0, L"Try to set a HW BP here", L"Test", 0);
    return 0;
}

LONG NTAPI VectorHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT Context = ExceptionInfo->ContextRecord;

    if (Context->Dr0 != 0 || Context->Dr1 != 0 || Context->Dr2 != 0 || Context->Dr3 != 0)
    {
        MessageBoxW(0, L"HW BP found -> ExceptionInfo!", L"Test", 0);
    }
#ifdef _WIN64
    Context->Rip = (DWORD_PTR)ExceptionContinue;
#else
    Context->Eip = (DWORD_PTR)ExceptionContinue;
#endif    
    return EXCEPTION_CONTINUE_EXECUTION;
}


void testContext()
{
    CONTEXT ctx2 = {0};
    ctx2.ContextFlags = CONTEXT_ALL;

    NtGetContextThread(NtCurrentThread, &ctx2);

    if ( !(ctx2.ContextFlags & CONTEXT_DEBUG_REGISTERS) || ctx2.Dr0 != 0 || ctx2.Dr1 != 0 || ctx2.Dr2 != 0 || ctx2.Dr3 != 0)
    {
         MessageBoxW(0, L"HW BP found -> NtGetContextThread!", L"Test", 0);
    }
}