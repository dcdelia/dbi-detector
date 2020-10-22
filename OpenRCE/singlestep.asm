; #########################################################################

      .586
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################
      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\comdlg32.inc
      
      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib
      
; #########################################################################  
    .data
DbgFoundTitle db "Debugger found:",0h
DbgFoundText db "Debugger has been found!",0h
DbgNotFoundTitle db "Debugger not found:",0h
DbgNotFoundText db "Debugger not found!",0h
    .code

start:

; MASM32 antiDebugger example
; coded by ap0x
; Reversing Labs: http://ap0x.headcoders.net

; Finds ring3/ring0 debuggers by executing exception with Trap flag.
; We set the trap flag so it will fire on next instruction, if debugger
; is not present SEH will fire, and if it is present and user chooses a
; step over debugging mode he will be caught!

ASSUME FS:NOTHING
PUSH offset _SehExit
PUSH DWORD PTR FS:[0]
MOV FS:[0],ESP

; Set Trap flag!

PUSHFD
XOR DWORD PTR[ESP],154h
POPFD

; If SEH doesn`t fire you are caught!

PUSH 30h
PUSH offset DbgFoundTitle
PUSH offset DbgFoundText
PUSH 0
CALL MessageBox
PUSH 0
CALL ExitProcess
RET
_Exit:
PUSH 40h
PUSH offset DbgNotFoundTitle
PUSH offset DbgNotFoundText
PUSH 0
CALL MessageBox
PUSH 0
CALL ExitProcess
RET

_SehExit:
POP FS:[0]
ADD ESP,4
JMP _Exit

end start