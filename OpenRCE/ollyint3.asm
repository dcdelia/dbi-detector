  .386
      .model flat, stdcall
      option casemap :none   ; case sensitive

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

    .data
msgTitle db "Execution status:",0h
msgText1 db "No debugger detected!",0h
msgText2 db "Debugger detected!",0h
    .code

start:

; MASM32 antiRing3Debugger example
; coded by ap0x
; Reversing Labs: http://ap0x.headcoders.net

; This code takes advantage of debugger not handleing INT3
; instructions correctly. If we set a SEH before INT3 executing
; INT3 instruction will fire SEH. If debugger is present it
; will just walk over INT3 and go straight forward.
; If debugger is not present exception will occure and exection
; will be handled by SEH.

; Set SEH
ASSUME FS:NOTHING
PUSH offset @Check
PUSH FS:[0]
MOV FS:[0],ESP

; Exception
INT 3h

PUSH 30h
PUSH offset msgTitle
PUSH offset msgText2
PUSH 0
CALL MessageBox

PUSH 0
CALL ExitProcess

; SEH handleing
@Check:
POP FS:[0]
ADD ESP,4

PUSH 40h
PUSH offset msgTitle
PUSH offset msgText1
PUSH 0
CALL MessageBox

PUSH 0
CALL ExitProcess

end start