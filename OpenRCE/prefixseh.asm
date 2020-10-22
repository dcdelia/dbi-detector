.386
      .model flat, stdcall
      option casemap :none   ; case sensitive

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

    .data
       DbgNotFoundTitle db "Debugger status:",0h
       DbgFoundTitle db "Debugger status:",0h
       DbgNotFoundText db "Debugger not found!",0h
       DbgFoundText db "Debugger found!",0h
    .data?
       SavedESP dd ?
    .code

start:

; MASM32 antiOlly example
; coded by ap0x
; Reversing Labs: http://ap0x.headcoders.net

; This example can detect Olly because OllyDBG does not handle
; prefixes well.
; If we insert prefix before one byte instruction that fires-up
; SEH OllyDBG will ignore it and walk right over it.
; If debugger is not present SEH will fire and continue code execution
; in SEH handler.

ASSUME FS:NOTHING
PUSHAD
MOV DWORD PTR[SavedESP],ESP ;Save ESP
PUSH offset SehContinue
PUSH DWORD PTR FS:[0]
MOV DWORD PTR FS:[0],ESP

db 0F3h,64h ;Prefix
db 0F1h ;1 byte INT 1h
POP DWORD PTR FS:[0]
ADD ESP,4
POPAD

PUSH 30h
PUSH offset DbgFoundTitle
PUSH offset DbgFoundText
PUSH 0
CALL MessageBox

RET

  SehContinue:
POP DWORD PTR FS:[0]
MOV ESP,DWORD PTR[SavedESP] ;Restore ESP
POPAD

PUSH 40h
PUSH offset DbgNotFoundTitle
PUSH offset DbgNotFoundText
PUSH 0
CALL MessageBox

RET

end start