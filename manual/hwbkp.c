#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// code adapted from ShowStopper project
// (the one from BH2012 did not reveal DRio)

enum HWBRK_TYPE
{
    HWBRK_TYPE_CODE,
    HWBRK_TYPE_READWRITE,
    HWBRK_TYPE_WRITE,
};

enum HWBRK_SIZE
{
    HWBRK_SIZE_1,
    HWBRK_SIZE_2,
    HWBRK_SIZE_4,
    HWBRK_SIZE_8,
};

typedef struct _HWBRK {
	void* a;
	HANDLE hT;
	DWORD Type;
	DWORD Size;
	HANDLE hEv;
	int iReg;
	int Opr;
	BOOL SUCC;
} HWBRK ;

void SetBits(DWORD_PTR* dw, int lowBit, int bits, int newValue) {
	DWORD_PTR mask = (1 << bits) - 1; 
	*dw = (*dw & ~(mask << lowBit)) | (newValue << lowBit);
}

static DWORD WINAPI th(LPVOID lpParameter)
{
	HWBRK* h = (HWBRK*)lpParameter;
	int j = 0;
	int y = 0;
    CONTEXT ct = {0};
    int FlagBit = 0;
	BOOL Dr0Busy = FALSE;
	BOOL Dr1Busy = FALSE;
	BOOL Dr2Busy = FALSE;
	BOOL Dr3Busy = FALSE;
    int st = 0;
    int le = 0;

    j = SuspendThread(h->hT);
	y = GetLastError();

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	j = GetThreadContext(h->hT,&ct);
	y = GetLastError();

	if (ct.Dr7 & 1)
		Dr0Busy = TRUE;
	if (ct.Dr7 & 4)
		Dr1Busy = TRUE;
	if (ct.Dr7 & 16)
		Dr2Busy = TRUE;
	if (ct.Dr7 & 64)
		Dr3Busy = TRUE;

	if (h->Opr == 1)
	{
		// Remove
		if (h->iReg == 0)
		{
			FlagBit = 0;
			ct.Dr0 = 0;
			Dr0Busy = FALSE;
		}
		if (h->iReg == 1)
		{
			FlagBit = 2;
			ct.Dr1 = 0;
			Dr1Busy = FALSE;
		}
		if (h->iReg == 2)
		{
			FlagBit = 4;
			ct.Dr2 = 0;
			Dr2Busy = FALSE;
		}
		if (h->iReg == 3)
		{
			FlagBit = 6;
			ct.Dr3 = 0;
			Dr3Busy = FALSE;
		}

		ct.Dr7 &= ~(1 << FlagBit);
	}
	else
	{
		if (!Dr0Busy)
		{
			h->iReg = 0;
			ct.Dr0 = (DWORD_PTR)h->a;
			Dr0Busy = TRUE;
		}
		else
			if (!Dr1Busy)
			{
				h->iReg = 1;
				ct.Dr1 = (DWORD_PTR)h->a;
				Dr1Busy = TRUE;
			}
			else
				if (!Dr2Busy)
				{
					h->iReg = 2;
					ct.Dr2 = (DWORD_PTR)h->a;
					Dr2Busy = TRUE;
				}
				else
					if (!Dr3Busy)
					{
						h->iReg = 3;
						ct.Dr3 = (DWORD_PTR)h->a;
						Dr3Busy = TRUE;
					}
					else
					{
						h->SUCC = FALSE;
						j = ResumeThread(h->hT);
						y = GetLastError();
						SetEvent(h->hEv);
						return 0;
					}
		ct.Dr6 = 0;
		if (h->Type == HWBRK_TYPE_CODE)
			st = 0;
		if (h->Type == HWBRK_TYPE_READWRITE)
			st = 3;
		if (h->Type == HWBRK_TYPE_WRITE)
			st = 1;
		if (h->Size == HWBRK_SIZE_1)
			le = 0;
		if (h->Size == HWBRK_SIZE_2)
			le = 1;
		if (h->Size == HWBRK_SIZE_4)
			le = 3;
		if (h->Size == HWBRK_SIZE_8)
			le = 2;

		SetBits(&ct.Dr7, 16 + h->iReg*4, 2, st);
		SetBits(&ct.Dr7, 18 + h->iReg*4, 2, le);
		SetBits(&ct.Dr7, h->iReg*2,1,1);
	}



	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	j = SetThreadContext(h->hT,&ct);
	y = GetLastError();

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	j = GetThreadContext(h->hT,&ct);
	y = GetLastError();

	j = ResumeThread(h->hT);
	y = GetLastError();

	h->SUCC = TRUE;

	SetEvent(h->hEv);
	return 0;
}

HANDLE SetHardwareBreakpoint(HANDLE hThread, DWORD Type, DWORD Size, void* s) {
    HANDLE hY;
    DWORD pid;
    HWBRK *h = malloc(sizeof(HWBRK));
    h->a = s;
    h->Size = Size;
    h->Type = Type;
    h->hT = hThread;

    if (hThread == GetCurrentThread())
    {
        pid = GetCurrentThreadId();
        h->hT = OpenThread(THREAD_ALL_ACCESS, 0, pid);
    }

    h->hEv = CreateEvent(0, 0, 0, 0);
    h->Opr = 0; // Set Break
    hY = CreateThread(0, 0, th, (LPVOID)h, 0, 0);
    WaitForSingleObject(h->hEv, INFINITE);
    CloseHandle(h->hEv);
    h->hEv = 0;

    if (hThread == GetCurrentThread())
    {
        CloseHandle(h->hT);
    }
    h->hT = hThread;

    if (!h->SUCC)
    {
        free(h);
        return 0;
    }

    return (HANDLE)h;
}

BOOL RemoveHardwareBreakpoint(HANDLE hBrk)
{
    HWBRK *h = (HWBRK *)hBrk;
    BOOL C = FALSE;
    DWORD pid;
    HANDLE hY;
    if (!h)
        return FALSE;


    if (h->hT == GetCurrentThread())
    {
        pid = GetCurrentThreadId();
        h->hT = OpenThread(THREAD_ALL_ACCESS, 0, pid);
        C = TRUE;
    }

    h->hEv = CreateEvent(0, 0, 0, 0);
    h->Opr = 1; // Remove Break
    hY = CreateThread(0, 0, th, (LPVOID)h, 0, 0);
    WaitForSingleObject(h->hEv, INFINITE);
    CloseHandle(h->hEv);
    h->hEv = 0;

    if (C)
    {
        CloseHandle(h->hT);
    }

    free(h);
    return TRUE;
}

static LONG WINAPI InstructionCountingExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		pExceptionInfo->ContextRecord->Eax += 1;
		pExceptionInfo->ContextRecord->Eip += 1;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(naked) DWORD WINAPI InstructionCountingFunc(LPVOID lpThreadParameter)
{
	DWORD cnt;
    __asm
	{
		xor eax, eax
		nop
		nop
		nop
		nop
        mov cnt, eax
		cmp al, 4
		jne being_debugged
	}
    
    printf("Count: %d\n", cnt);
	ExitThread(FALSE);

being_debugged:
    printf("Count: %d\n", cnt);
	ExitThread(TRUE);
}

const size_t m_nInstructionCount = 4;
PVOID m_pThreadAddr;
HANDLE m_hHwBps[4];

BOOL AntiDebug_InstructionCounting() {
	PVOID hVeh = NULL;
	HANDLE hThread = NULL;
	BOOL bDebugged = FALSE;
    DWORD dwThreadExitCode;
    size_t i;

	__try
	{
		hVeh = AddVectoredExceptionHandler(TRUE, InstructionCountingExceptionHandler);
		// if (!hVeh)
		// 	__leave;

		hThread = CreateThread(0, 0, InstructionCountingFunc, NULL, CREATE_SUSPENDED, 0);
		// if (!hThread)
		// 	__leave;

		m_pThreadAddr = &InstructionCountingFunc;
		if (*(PBYTE)m_pThreadAddr == 0xE9)
			m_pThreadAddr = (PVOID)((DWORD)m_pThreadAddr + 5 + *(PDWORD)((PBYTE)m_pThreadAddr + 1));

		for (i = 0; i < m_nInstructionCount; i++)
			m_hHwBps[i] = SetHardwareBreakpoint(hThread, HWBRK_TYPE_CODE, HWBRK_SIZE_1, (PVOID)((DWORD)m_pThreadAddr + 2 + i));

		ResumeThread(hThread);
		WaitForSingleObject(hThread, INFINITE);

		if (TRUE == GetExitCodeThread(hThread, &dwThreadExitCode))
			bDebugged = (TRUE == dwThreadExitCode);
	}
	__finally
	{
		if (hThread)
			CloseHandle(hThread);

		for (i = 0; i < 4; i++)
		{
			if (m_hHwBps[i])
				RemoveHardwareBreakpoint(m_hHwBps[i]);
		}

		if (hVeh)
			RemoveVectoredExceptionHandler(hVeh);
	}

	return bDebugged;
}

int main() {
    BOOL ret = AntiDebug_InstructionCounting();
    printf("Result: %d\n", ret);
    return 0;
}