; ----------------------------------------------------------------------
;
; Author: halsten
; E-mail: halsten [at] gmail [dot] com
; Website: http://iamhalsten.thecoderblogs.com/
;
; -----------------------------------------------------------------------

.386
.model flat, stdcall
option casemap :none   ; case sensitive
; locals
; jumps
UNICODE=0
;include w32.inc
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

;extrn SetUnhandledExceptionFilter :PROC

.data
szMsgTitle db "CMPXCHG8B instruction usage with the LOCK prefix", 00h
szDebuggerFound db "Program doesn't run properly, it has been changed while running!", 00h
szDebuggerNotFound db "SEH service was called (OK)", 00h

DelayESP dd 0
PreviousSEH dd 0

.code
EntryPoint PROC
mov [DelayESP],esp
push offset @@Error
call SetUnhandledExceptionFilter
mov [PreviousSEH], eax

db 0F0h, 0F0h, 0C7h, 0C8h

jmp @@DebuggerFound
push dword ptr [PreviousSEH]
call SetUnhandledExceptionFilter

  @@DebuggerNotFound:
push 0
push offset szMsgTitle
push offset szDebuggerNotFound
push 0
call MessageBoxA

push -1
call ExitProcess

  @@DebuggerFound:
push 0
push offset szMsgTitle
push offset szDebuggerFound
push 0
call MessageBoxA

push -1
call ExitProcess

  @@Error:
mov esp, [DelayESP]
push offset @@DebuggerNotFound
ret
EntryPoint ENDP


end EntryPoint