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
       DbgNotFoundTitle db "Debugger status:",0h
       DbgFoundTitle db "Debugger status:",0h
       DbgNotFoundText db "Debugger not found!",0h
       DbgFoundText db "Debugger found!",0h

; TLS Structure {See PE Format info}

       dd offset Tls1
       dd offset Tls2
       dd offset Tls3
       dd offset TlsCallBack
       dd 0
       dd 0
       Tls1 dd     0
       Tls2 dd     0
       Tls3 dd     0
       TlsCallBack dd  offset TLS
       dd     0
       dd     0
    .data?
       TLSCalled db ?
    .code

start:

; MASM32 antiOllyDBG example
; coded by ap0x
; Reversing Labs: http://ap0x.headcoders.net

; This example combines IsDebuggerPresent API with TLS-CallBack.
; TLS-CallBack is a part of TLS Structure and it is used for
; calling code execution before and after main application code execution.

; Change TLS Table to 0x00003046, size 0x18 with LordPE or xPELister

PUSH 0
CALL ExitProcess
RET

; Code below is executed before .code section
TLS:
; TLSCalled flag indicates that TLS is called only once on application
; initialization. It can be called on application exit again. This switch
; disables that.

CMP BYTE PTR[TLSCalled],1
JE @exit
MOV BYTE PTR[TLSCalled],1
CALL IsDebuggerPresent

CMP EAX,1
JE @DebuggerDetected

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

RET

end start