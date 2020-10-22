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
       krnl db "kernel32.dll",0h
       chkrdbg db "CheckRemoteDebuggerPresent",0h
    .data?
       IsItPresent dd ?
    .code

start:

; MASM32 antiRing3Debugger example
; coded by ap0x
; Reversing Labs: http://ap0x.headcoders.net

; CheckRemoteDebuggerPresent is function similar to IsDebuggerPresent.
; This function is available only in Windows NT and it outputs TRUE or
; FALSE value if debugger is present in selected process.

; Load the function via GetProcAddress

PUSH offset krnl ;kernel32.dll
CALL LoadLibrary

PUSH offset chkrdbg ;CheckRemoteDebuggerPresent
PUSH EAX
CALL GetProcAddress

; IsItPresent variable will store the resault

PUSH offset IsItPresent
PUSH -1
CALL EAX

MOV EAX,DWORD PTR[IsItPresent]
TEST EAX,EAX
JNE @DebuggerDetected

PUSH 40h
PUSH offset DbgNotFoundTitle
PUSH offset DbgNotFoundText
PUSH 0
CALL MessageBox

JMP @exit
  @DebuggerDetected:

PUSH 30h
PUSH offset DbgFoundTitle
PUSH offset DbgFoundText
PUSH 0
CALL MessageBox

  @exit:

PUSH 0
CALL ExitProcess

end start