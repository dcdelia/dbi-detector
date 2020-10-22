;---------------------------------------------------------------------------
; Int 2Dh debugger detection and code obfuscation - ReWolf^HTB
;
; Date: 14.III.2007
;
;
; I. BACKGROUND
;
;       Possibly new method of debugger detection, and nice way for code
;    obfuscation.
;
;
; II. DESCRIPTION
;
;       Int 2Dh is used by ntoskrnl.exe to play with DebugServices (ref1),
;    but we can use it also in ring3 mode. If we try to use it in normal
;    (not debugged) application, we will get exception. However if we will
;    attach debugger, there will be no exception.
;
;       push    offset _seh     ;\
; push    fs:[0]          ; > set SEH
;       mov     fs:[0], esp     ;/
;
;       int     2dh             ; if debugger attached it will run normally,
;                               ; else we've got exception
;       nop
;       pop     fs:[0]          ;\ clear SEH
;       add     esp, 4          ;/
;
;       ...
;       debugger detected
;       ...
;
;       _seh:
;       debugger not detected
;
;    It can also crash SoftIce DbgMsg driver (ref2).
;
;       Besides this, int 2Dh can also be used as code obfuscation method.
;    With attached debugger, after executing int 2Dh, system skips one byte
;    after int 2Dh:
;
;       int     2dh
;       nop                     ; never executed
;       ...
;
;    If we'll execute step into/step over on int 2Dh different debuggers
;    will behave in different way:
;
;       OllyDbg - run until next breakpoint (if we have any)
;       Visual Studio - stop on instruction after nop in our example
;       WinDbg - stop after int 2dh (always even if we 'Go')
;
;    Only OllyDbg behaves correctly if we permit to run process without any
;    breaks. We can create self debuggable application (as in attached
;    example) that will take advantages of int 2Dh code obfuscation.
;
;
; III. Links
;
;    1. http://www.vsj.co.uk/articles/display.asp?id=265
;    2. http://www.piotrbania.com/all/adv/sice-adv.txt
;
;
; IV. Thanks
;
;    omega red, Gynvael Coldwind, ved, Piotr Bania
;
;
; comments, suggestions, job opportunities: rewolf@poczta.onet.pl
;                                           http://www.rewolf.prv.pl
;---------------------------------------------------------------------------
;
;change file extensionton .asm and compile
;tested on: Win XP Pro sp2 (x86), Win 2k3 server (x64), Vista Ultimate (x64)
;
;---------------------------------------------------------------------------
.386
.model flat, stdcall
option casemap:none
;---------------------------------------------------------------------------
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32
includelib \masm32\lib\user32
;---------------------------------------------------------------------------
.data
procinfo PROCESS_INFORMATION <0>
startinfo STARTUPINFO <0>
debugEvt DEBUG_EVENT<0>
_str db 100 DUP (0)
_fmt db 'eax: %08X',0dh,0ah,'ebx: %08X',0dh,0ah,'ecx: %08X',0dh,0ah,
'edx: %08X',0

;---------------------------------------------------------------------------
;CLOAKxB -> cloaks x bytes instruction

CLOAK1B macro ;int.int
int 2dh
db 0cdh
endm

CLOAK2B macro ;int.ret
int 2dh
db 0c2h
endm

CLOAK3B macro ;int.enter
int 2dh
db 0c8h
endm

CLOAK4B macro ;int.call
int 2dh
db 0e8h
endm

;If you find some other 'cloaking' opcodes i.e. 5 or more bytes please send
;me e-mail ;-)

;---------------------------------------------------------------------------
;sample mov r32, val macro

MOV_REG macro reg1: REQ, val1:REQ, val2:REQ, val3:REQ, val4:REQ
int 2dh
int reg1 ;\
int val3 ; >mov eax, (val1)CD(val3)CD
int val1 ;/
int 2dh
;enter 78xxh, 90h ;  mov al, val4
db 0c8h, reg1 - 8, val4, 90h
int 2dh
;enter 0xxc1h, 10h ;  ror eax, 10h
db 0c8h, 0c1h, reg1 + 10h, 10h
int 2dh
;enter 34xxh, 90h ;  mov al, val2
db 0c8h, reg1 - 8, val2, 90h
int 2dh
;enter 0xxc1h, 10h ;  ror eax, 10h
db 0c8h, 0c1h, reg1 + 10h, 10h
endm
;---------------------------------------------------------------------------
MOV_EAX macro val1:REQ, val2:REQ, val3:REQ, val4:REQ
MOV_REG 0b8h, val1, val2, val3, val4
endm

MOV_EBX macro val1:REQ, val2:REQ, val3:REQ, val4:REQ
MOV_REG 0bbh, val1, val2, val3, val4
endm

MOV_ECX macro val1:REQ, val2:REQ, val3:REQ, val4:REQ
MOV_REG 0b9h, val1, val2, val3, val4
endm

MOV_EDX macro val1:REQ, val2:REQ, val3:REQ, val4:REQ
MOV_REG 0bah, val1, val2, val3, val4
endm
;---------------------------------------------------------------------------
.code
start:


assume fs:nothing
push offset _seh ;\
push fs:[0] ; > set SEH
mov fs:[0], esp ;/

int 2dh ; if debugger attached it will run normally,
; else we've got exception
nop
pop fs:[0] ;\ clear SEH
add esp, 4 ;/

;---------------------------------------------------------------------------

MOV_EAX 98h ,76h, 54h, 32h ; mov eax, 98765432h
MOV_EBX 12h, 34h, 56h, 78h ; mov ebx, 12345678h
MOV_ECX 0abh, 0cdh, 0efh, 0 ; mov ecx, 0abcdef00h
MOV_EDX 90h, 0efh, 0cdh, 0abh ; mov edx, 90efcdabh

;---------------------------------------------------------------------------

CLOAK1B
push edx
CLOAK1B
push ecx
CLOAK1B
push ebx
CLOAK1B
push eax
CLOAK4B
push offset _fmt
CLOAK4B
push offset _str
CLOAK4B
call wsprintf
CLOAK3B
add esp, 18h
CLOAK2B
push 0
CLOAK4B
push offset _str
CLOAK4B
push offset _str
CLOAK2B
push 0
CLOAK4B
call MessageBox
CLOAK2B
push 0
CLOAK2B
jmp _end2
;---------------------------------------------------------------------------
_seh:
; setting mini-debugger ;-)
push offset procinfo
push offset startinfo
push 0
push 0
push DEBUG_PROCESS
push 0
push 0
push 0
call GetCommandLine
push eax
push 0
call CreateProcess

_dbgloop:
push INFINITE
push offset debugEvt
call WaitForDebugEvent

cmp debugEvt.dwDebugEventCode, EXIT_PROCESS_DEBUG_EVENT
je _end

push DBG_CONTINUE
push debugEvt.dwThreadId
push debugEvt.dwProcessId
call ContinueDebugEvent

jmp _dbgloop


_end: push 0
_end2: call ExitProcess
end start