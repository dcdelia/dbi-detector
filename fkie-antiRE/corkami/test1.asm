; #### License ############################################################
;
; Published as open source under "BSD New" license
;
; Copyright (c) 2011-2012, Daniel Plohmann
; All rights reserved.
;
; Redistribution and use in source and binary forms,
; with or without modification,
; are permitted provided that the following conditions are met:
;
;  * Redistributions of source code must retain the above copyright notice,
;    this list of conditions and the following disclaimer.
;  * Redistributions in binary form must reproduce the above copyright notice,
;    this list of conditions and the following disclaimer in the documentation
;    and/or other materials provided with the distribution.
;  * The names of the authors may not be used to endorse or promote products
;    derived from this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.
;
; #### MASM 32 setup and includes #########################################

.586
.MODEL flat, stdcall
OPTION casemap :none
INCLUDE \masm32\include\windows.inc
INCLUDE \masm32\include\masm32.inc
INCLUDE \masm32\include\user32.inc
INCLUDE \masm32\include\kernel32.inc
INCLUDE \masm32\include\ntdll.inc
INCLUDE \masm32\include\comdlg32.inc
INCLUDE \masm32\include\advapi32.inc
INCLUDE \masm32\include\shell32.inc
INCLUDE \masm32\include\msvcrt.inc

INCLUDELIB \masm32\lib\masm32.lib
INCLUDELIB \masm32\lib\user32.lib
INCLUDELIB \masm32\lib\kernel32.lib
INCLUDELIB \masm32\lib\ntdll.lib
INCLUDELIB \masm32\lib\comdlg32.lib
INCLUDELIB \masm32\lib\advapi32.lib
INCLUDELIB \masm32\lib\shell32.lib
INCLUDELIB \masm32\lib\msvcrt.lib


;;; workaround - broken APIs though
IFNDEF Process32FirstA
Process32FirstA PROTO :DWORD,:DWORD
ENDIF

IFNDEF Process32First
Process32First TEXTEQU <Process32FirstW>
ENDIF

IFNDEF Process32NextA
Process32NextA PROTO :DWORD,:DWORD
ENDIF

IFNDEF Process32Next
Process32Next TEXTEQU <Process32NextW>
ENDIF

; #########################################################################
; #########################################################################

.DATA

; #### Flags to easily allow tailored compilations ########################

dwWaitForAnyKey        DD 1h
dwPrintToFile          DD 0h
dwPrintOnlyFailedTests DD 0h

; #### Strings used by the tool ###########################################

szPrologue     DB "This is a short prologue to explain the three TLS callbacks.", 0h
szPrologue_1   DB " Callback 1: This message.", 0h
szPrologue_2   DB " Callback 2: A TLS-based check that identifies debuggers when they run a thread to attach to process. Explained later during the program.", 0h
szPrologue_3   DB " Callback 3: Setup and argument parsing.", 0h
szPrologue_4   DB "If you did not notice the callbacks in first place, it is too late now anyway ;)", 0h

szWelcomeTitle DB "Welcome to the interactive AntiRE Summary RC 2 (June 11th, 2012)", 0Dh, 0Ah
               DB "created 2011/2012 by Daniel Plohmann and Christopher Kannen", 0Dh, 0Ah
               DB "contact: plohmann (at) cs (dot) uni-bonn (dot) de", 0Dh, 0Ah, 0Dh, 0Ah, 0h

szDisclaimerText DB " This tool summarizes trivially implemented versions of more or less common", 0Dh, 0Ah
                 DB " assembler code fragments with the goal to complicate the analysis of", 0Dh, 0Ah
                 DB " oftentimes malicious programs. Most tests aim at recognizing the presence", 0Dh, 0Ah
                 DB " of a debugger, detecting single-stepping or tracing, others modify memory", 0Dh, 0Ah
                 DB " dynamically, or allow detection of virtualized environments.", 0Dh, 0Ah
                 DB " Documentation on many of the techniques can be found in numerous places", 0Dh, 0Ah
                 DB " already. Our goal is to provide a collection of running code that is easily", 0Dh, 0Ah
                 DB " accessible to novice reverse engineers and can be directly used to experiment", 0Dh, 0Ah
                 DB " with these techniques, with intended use for educational purposes and to", 0Dh, 0Ah
                 DB " harden the own analysis environment against these mechanisms.", 0Dh, 0Ah
                 DB 0Dh, 0Ah
                 DB " We tried to limit the number of references for the tests to as few as", 0Dh, 0Ah
                 DB " possible in order to create a compact overview of related sources.", 0Dh, 0Ah
                 DB " The main inspirations and sources", 0Dh, 0Ah
                 DB " for many of the tests included in this project are:", 0Dh, 0Ah
                 DB " - Peter Ferrie's 'The Ultimate Anti-Debugging Reference' (PF-TUADR)", 0Dh, 0Ah
                 DB "   (http://pferrie.host22.com/)", 0Dh, 0Ah
                 DB " - Ange Albertini's 'corkami' project (RE experiments and documentations)", 0Dh, 0Ah
                 DB "   (http://code.google.com/p/corkami/)", 0Dh, 0Ah
                 DB " - 'The OpenRCE Anti RE Techniques Database', mainly driven by ap0x", 0Dh, 0Ah
                 DB "   (http://www.openrce.org/reference_library/anti_reversing)", 0Dh, 0Ah
                 DB " - Nicolas Falliere's 'Windows Anti-Debug Reference'", 0Dh, 0Ah
                 DB "   (http://www.symantec.com/connect/articles/windows-anti-debug-reference)", 0Dh, 0Ah
                 DB " - Joshua Jackon's 'Anti-Reverse Engineering Guide' implementations", 0Dh, 0Ah
                 DB "   (http://tuts4you.com/download.php?view.2516)", 0Dh, 0Ah
                 DB " The remaining individual techniques are attributed to the source first", 0Dh, 0Ah
                 DB " identified while searching. If you have the feeling that you are missing", 0Dh, 0Ah
                 DB " in these credits, if you want to contribute to the project, or if you", 0Dh, 0Ah
                 DB " just want to provide us feedback, please fell free to contact us ", 0Dh, 0Ah
                 DB " via the email address listed in the header!", 0Dh, 0Ah
                 DB 0Dh, 0Ah
                 DB "Commandline options: ", 0Dh, 0Ah
                 DB " -a   automated execution (without keyboard interrupts)", 0Dh, 0Ah
                 DB " -o   output report to file ./anti_re_output.log", 0Dh, 0Ah, 0Dh, 0Ah, 0h

szTimingRdtscTitle  DB "RDTSC Time Trap", 0Dh, 0Ah, 0h
szTimingRdtscRef    DB "Reference: PF-TUADR - 7.C", 0Dh, 0Ah, 0h
szTimingRdtscText   DB " The basic assumption of this technique is that native execution of code will", 0Dh, 0Ah
                    DB " always be faster than emulated or manually debugged execution.", 0Dh, 0Ah
                    DB " First, an inital time measurement is made via the assembler instruction RDTSC,", 0Dh, 0Ah
                    DB " which reads the current timestamp-counter into EDX:EAX.", 0Dh, 0Ah
                    DB " Next, an arbitrary sequence of instructions is executed. Finally, a second", 0Dh, 0Ah
                    DB " time measurement is made again with RDTSC and the time difference", 0Dh, 0Ah
                    DB " is calculated. If this difference exceeds a given upper bound, the presence", 0Dh, 0Ah
                    DB " of an analysis system can be assumed.", 0Dh, 0Ah, 0h

szRtlProcessFlsDataTitle DB "Execution Takeover: RtlProcessFlsData", 0Dh, 0Ah, 0h
szRtlProcessFlsDataRef   DB "Reference: PF-TUADR - 7.G.x", 0Dh, 0Ah, 0h
szRtlProcessFlsDataText  DB " Introduced in Windows Vista, the ntdll.RtlProcessFlsData() API can be used", 0Dh, 0Ah
                         DB " to execute code at a previously specified location in memory. This can be used", 0Dh, 0Ah
                         DB " to takeover execution from a debugger.", 0Dh, 0Ah, 0h

szTimingGtcTitle    DB "kernel32.GetTickCount() Time Trap", 0Dh, 0Ah, 0h
szTimingGtcRef      DB "Reference: PF-TUADR - 7.C", 0Dh, 0Ah, 0h
szTimingGtcText     DB " This technique is in its approach similar to the RDTSC time trap but instead", 0Dh, 0Ah
                    DB " of an assembler instruction the API function kernel32.GetTickCount() is used", 0Dh, 0Ah
                    DB " to perform time measurements. GetTickCount() returns the number of", 0Dh, 0Ah
                    DB " milliseconds passed since the system was booted up.", 0Dh, 0Ah, 0h

szTimingQpcTitle DB "kernel32.QueryPerformanceCounter() Time Trap", 0Dh, 0Ah, 0h
szTimingQpcRef   DB "Reference: PF-TUADR - 7.C", 0Dh, 0Ah, 0h
szTimingQpcText  DB " This test is very similar to the other timing tests, but it uses", 0Dh, 0Ah
                 DB " the Query Performance Counter for the measurement. The Query", 0Dh, 0Ah
                 DB " Performance Counter is a hardware based clock generator working at", 0Dh, 0Ah
                 DB " 3.19 MHz (respectively one tick every 0.313 ms.)", 0Dh, 0Ah, 0h

szTimingRdpmcTitle  DB "RDPMC Time Trap", 0Dh, 0Ah, 0h
szTimingRdpmcRef    DB "Reference: PF-TUADR - 7.C", 0Dh, 0Ah, 0h
szTimingRdpmcText   DB " This test is one more test to detect a debugger by measuring the time that", 0Dh, 0Ah
                    DB " passes between the exeution of some instructions. It uses the RDPMC", 0Dh, 0Ah
                    DB " instruction which requires that the PCE flag is set in the CR4 register.", 0Dh, 0Ah
                    DB " This is not the default. As the flags in CR4 cannot easily be changed", 0Dh, 0Ah
                    DB " from user-mode, this requires interaction with the kernel.", 0Dh, 0Ah, 0h

szPEBGlobalFlagsTitle DB " Check NtGlobalFlags via PEB", 0Dh, 0Ah, 0h
szPEBGlobalFlagsRef   DB "Reference: PF-TUADR - 1", 0Dh, 0Ah, 0h
szPEBGlobalFlagsText  DB " In this test we take a look at the Process Environment Block (PEB). The PEB is", 0Dh, 0Ah
                      DB " a Win32 data structure and mostly used by the operating system internally.", 0Dh, 0Ah
                      DB " But some fields are also used by debuggers and set, if a process is debugged.", 0Dh, 0Ah
                      DB " This test checks the fields: NtGlobalFlag, ProcessHeapFlags and", 0Dh, 0Ah
                      DB " ProcessHeapForceFlags.", 0Dh, 0Ah, 0h

szIsDebuggerPresentTitle DB "kernel32.IsDebuggerPresent() Test", 0Dh, 0Ah, 0h
szIsDebuggerPresentRef   DB "Reference: PF-TUADR - 7.D.vii", 0Dh, 0Ah, 0h
szIsDebuggerPresentText  DB " In this test the API function kernel32.IsDebuggerPresent() is called.", 0Dh, 0Ah
                         DB " The function returns 01h into eax if the current process is being debugged.", 0Dh, 0Ah
                         DB " This is claimed to be one of the most common Anti Debugging Mechanisms", 0Dh, 0Ah
                         DB " because it is so easily implemented.", 0Dh, 0Ah, 0h

szIsDebuggerPresent2Title DB "Alternative IsDebuggerPresent() Test", 0Dh, 0Ah, 0h
szIsDebuggerPresent2Ref   DB "Reference: PF-TUADR - 7.D.vii", 0Dh, 0Ah, 0h
szIsDebuggerPresent2Text  DB " This test works like the previous 'IsDebuggerPresent() Test', but the ", 0Dh, 0Ah
                          DB " functioning of the API call is now represented indirectly by accessing ", 0Dh, 0Ah
                          DB " the PEB.BeingDebugged Flag via mov instructions.", 0Dh, 0Ah, 0h

szFindWindowTitle DB "user32.FindWindow()", 0Dh, 0Ah, 0h
szFindWindowRef   DB "Reference: PF-TUADR - 7.E.i", 0Dh, 0Ah, 0h
szFindWindowText  DB " In this test we first try to find a window whose label says 'OLLYDBG' by using", 0Dh, 0Ah
                  DB " the API call 'FindWindow'. Finding this window name means that the", 0Dh, 0Ah
                  DB " program OllyDbg is probably currently running and we assume it is", 0Dh, 0Ah
                  DB " running to debug our process. The second part repeats the test with 'SHADOW'", 0Dh, 0Ah
                  DB " instead of 'OLLYDBG' in order to find the OllyShadow Plugin which alters the", 0Dh, 0Ah
                  DB " window name of OllyDbg.", 0Dh, 0Ah, 0h

szRemoteDebuggerTitle DB "kernel32.CheckRemoteDebuggerPresent() Test", 0Dh, 0Ah, 0h
szRemoteDebuggerRef   DB "Reference: PF-TUADR - 7.D.i", 0Dh, 0Ah, 0h
szRemoteDebuggerText  DB " This test is comparable to the 'IsDebuggerPresent() Test' but it's only", 0Dh, 0Ah
                      DB " working on NT Systems.", 0Dh, 0Ah
                      DB " The API function kernel32.CheckRemoteDebuggerPresent() is called", 0Dh, 0Ah
                      DB " in order to determine whether a remote debugger is attached. It returns", 0Dh, 0Ah
                      DB " True if a debugger is working on our process, else False.", 0Dh, 0Ah
                      DB " Internally, a call to ntdll.QueryInformationProcess with", 0Dh, 0Ah
                      DB " argument ProcessInformationClass = ProcessDebugPort (0x7) is made.", 0Dh, 0Ah, 0h

szNtQueryInformationTitle DB "ntdll.NtQueryInformationProcess() Test", 0Dh, 0Ah, 0h
szNtQueryInformationRef   DB "Reference: PF-TUADR - 7.D.viii", 0Dh, 0Ah, 0h
szNtQueryInformationText  DB " The API call to ntdll.NtQueryInformationProcess() can be used to return a", 0Dh, 0Ah
                          DB " debugger's port number if one is attached to the process. This needs the", 0Dh, 0Ah
                          DB " ProcessInformationClass parameter to be set to 0x7. If no debugger is present,", 0Dh, 0Ah
                          DB " it returns 0.", 0Dh, 0Ah
                          DB " This is a lower-level variant of the ntdll.CheckRemoteDebuggerPresent() Test.", 0Dh, 0Ah, 0h

szNtQuerySystemInformationTitle DB "NtQuerySystemInformation: SystemKernelDebuggerInformation Test", 0Dh, 0Ah, 0h
szNtQuerySystemInformationRef   DB "Reference: PF-TUADR - 7.E.iii", 0Dh, 0Ah, 0h
szNtQuerySystemInformationText  DB " The ntdll.NtQuerySystemInformation() API provides various means to detect", 0Dh, 0Ah
                                DB " a debugger. By using the information class SystemKernelDebuggerInformation,", 0Dh, 0Ah
                                DB " two elements of indices for a kernel debugger can be derived. After the", 0Dh, 0Ah
                                DB " call AL will contain the value of KdDebuggerEnabled and AH the value of", 0Dh, 0Ah
                                DB " KdDebuggerNotPresent. These values are queried from the kernel and thus", 0Dh, 0Ah
                                DB " not trivial to conceal.", 0Dh, 0Ah, 0h

szOllyInvisibleTitle DB "OllyInvisible Detection", 0Dh, 0Ah, 0h
szOllyInvisibleRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szOllyInvisibleText  DB " We call the API function CsrGetProcessId. If OllyInvisible is running, this API", 0Dh, 0Ah
                     DB " call always returns 0 instead of the correct PID of CSRSS.exe as intended.", 0Dh, 0Ah
                     DB " In case we find a zero, OllyInvisible has been caught.", 0Dh, 0Ah, 0h

szSingleStepDetectionTitle DB "Single Step Detection", 0Dh, 0Ah, 0h
szSingleStepDetectionRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szSingleStepDetectionText  DB " This Test determines the presence of a debugger by manually setting the trap", 0Dh, 0Ah
                           DB " flag (push flags to stacks, XOR with 0x100, pop flags) and proceeding", 0Dh, 0Ah
                           DB " execution. If the next instruction is executed without the presence of", 0Dh, 0Ah
                           DB " a debugger, an exception is caused which will be handled by the installed", 0Dh, 0Ah
                           DB " SEH. If the exception is caught be the debugger, the control flow deviates.", 0Dh, 0Ah
                           DB " Furthermore, tracing will also be detected through this custom", 0Dh, 0Ah
                           DB " modification of the trap flag.", 0Dh, 0Ah, 0h

szOpenProcessTitle DB "OllyDbg - Open Process", 0Dh, 0Ah, 0h
szOpenProcessRef   DB "Reference: PF-TUADR - 7.B.i", 0Dh, 0Ah, 0h
szOpenProcessText  DB " The HideDebugger plugin for OllyDbg inserts a JMP FAR (0xEA) instruction to", 0Dh, 0Ah
                   DB " the OpenProcess API. This test calls the GetProcAddress function from kernel32", 0Dh, 0Ah
                   DB " with 'OpenProcess' as parameter and compares the first byte of the returned", 0Dh, 0Ah
                   DB " address against 0xEA.", 0Dh, 0Ah, 0h

szRegistryKeyTitle DB "OllyDbg - Registry Key", 0Dh, 0Ah, 0h
szRegistryKeyRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szRegistryKeyText  DB " In this test we look for a registry key created by OllyDbg:", 0Dh, 0Ah
                   DB " HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger", 0Dh, 0Ah
                   DB " If this key exists, OllyDbg might installed on the system.", 0Dh, 0Ah
                   DB " However, it has to be remarked that this key is also created by", 0Dh, 0Ah
                   DB " legitimate, unsuspicious software such as Visual Studio and thus.", 0Dh, 0Ah
                   DB " not reliable.", 0Dh, 0Ah, 0h

szCMPXCHG8BTitle DB "LOCK CMPXCHG8B", 0Dh, 0Ah, 0h
szCMPXCHG8BRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szCMPXCHG8BText  DB " The CMPXCHG8B statement is encoded in the byte sequence F0 0F C7 C8.", 0Dh, 0Ah
                 DB " Executing it will always cause an exception which should be handled by our", 0Dh, 0Ah
                 DB " own exception handler. If it is caught by the debugger, control flow may", 0Dh, 0Ah
                 DB " deviate. Furthermore, LOCK CMPXCHG8B may not be executed correctly in some", 0Dh, 0Ah
                 DB " emulators or virtual environments. Originally, this test aimed against", 0Dh, 0Ah
                 DB " SoftIce, which would stop execution on this instruction if the", 0Dh, 0Ah
                 DB " corresponding option was not properly set in the configuration.", 0Dh, 0Ah
                 DB " Additionally, the bytes FO OF C7 C8 cause a system lock-up on processors", 0Dh, 0Ah
                 DB " of the pre-Pentium Pro era.", 0Dh, 0Ah, 0

szAnalysisDriverTitle DB "Analysis Tools Driver Detection", 0Dh, 0Ah, 0h
szAnalysisDriverRef   DB "Reference: PF-TUADR - 7.B.iii", 0Dh, 0Ah, 0h
szAnalysisDriverText  DB " This test searches for well-known driver names like 'SICE' and 'FILEM'", 0Dh, 0Ah
                      DB " and others used by the various analysis tools with a ring0 component.", 0Dh, 0Ah
                      DB " It tries to gain access to said objects via kernel32.CreateFile() with", 0Dh, 0Ah
                      DB " argument OpenExisting and if an exception occurs this is a hint that", 0Dh, 0Ah
                      DB " one of said tools is running.", 0Dh, 0Ah, 0h


szSoftIceRegistryTitle DB "SoftIce Driver Detection", 0Dh, 0Ah, 0h
szSoftIceRegistryRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szSoftIceRegistryText  DB " This Tests works against the SoftIce debugger. If it is installed we can", 0Dh, 0Ah
                       DB " likely find a registry key indicating its presence at", 0Dh, 0Ah
                       DB " HKLM\SOFTWARE\NuMega\DriverStudio\InstallDir.", 0Dh, 0Ah, 0h

szSoftIceWinICETitle DB "SoftIce WinICE.dat Detection", 0Dh, 0Ah, 0h
szSoftIceWinICERef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szSoftIceWinICEText  DB " This test is similar to the 'SoftIce Driver Detection' test as also system", 0Dh, 0Ah
                     DB " properties are examined for detecting the presence of a SoftICE installation.", 0Dh, 0Ah
                     DB " Here we try to find a SoftIce file in the Windows folder called", 0Dh, 0Ah
                     DB " '\system32\drivers\WinICE.dat'.", 0Dh, 0Ah, 0h

szRing3DebuggerTitle DB "Detection based on memory debug codes", 0Dh, 0Ah, 0h
szRing3DebuggerRef   DB "Reference: PF-TUADR - 3", 0Dh, 0Ah, 0h
szRing3DebuggerText  DB " This test exploits Memory Debug Codes in order to detect a ring3 debugger.", 0Dh, 0Ah
                     DB " If a process is created with flag PROCESS_DEBUG, special heap API", 0Dh, 0Ah
                     DB " functions (ntdll.RtlDebugAllocateHeap) are used for allocation of memory", 0Dh, 0Ah
                     DB " This causes the pattern 0xFEEEFEEE to be written at the end of allocations,", 0Dh, 0Ah
                     DB " which in turn can be used for the detection of a ring3 debugger.", 0Dh, 0Ah, 0h

szInt3ExceptionTitle DB "OllyDbg - Int3 ", 0Dh, 0Ah, 0h
szInt3ExceptionRef   DB "Reference: PF-TUADR - 6.C", 0Dh, 0Ah, 0h
szInt3ExceptionText  DB " This test interrupts the program intentionally with an INT 3h. This Interrupt", 0Dh, 0Ah
                     DB " usually used by debuggers to replace an instruction in a running program and", 0Dh, 0Ah
                     DB " to mark it as a software break point. When encountering a INT 3h instruction,", 0Dh, 0Ah
                     DB " some Debuggers as e.g. older versions of OllyDbg will directly catch the", 0Dh, 0Ah
                     DB " exception caused by this instruction. If the exception is processed normally", 0Dh, 0Ah
                     DB " the expected control flow continues.", 0Dh, 0Ah, 0h

szInstructionPrefixDetectionTitle DB "OllyDbg - InstructionPrefixDetection ", 0Dh, 0Ah, 0h
szInstructionPrefixDetectionRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szInstructionPrefixDetectionText  DB " By setting a byte sequence like F3:64:F1 we create a series of ", 0Dh, 0Ah
                                  DB " prefixes (<REP> and <override FS>) before a one byte instruction,", 0Dh, 0Ah
                                  DB " in this case INT 0x1. Some debuggers cannot handle this and will", 0Dh, 0Ah
                                  DB " silently consume the exception for single-step break instead of passing", 0Dh, 0Ah
                                  DB " it on to the application, i.e. our SEH. This is valid atleast for", 0Dh, 0Ah
                                  DB " OllyDbg 1.10.", 0Dh, 0Ah, 0h

szMemoryBreakpointDetectionTitle DB "OllyDbg - Memory Breakpoint Detection ", 0Dh, 0Ah, 0h
szMemoryBreakpointDetectionRef   DB "Reference: PF-TUADR - 7.D.xv", 0Dh, 0Ah, 0h
szMemoryBreakpointDetectionText  DB " In this test page-guarded memory is created. If this this is executed", 0Dh, 0Ah
                                 DB " an exception will be fired which will be caught by our SEH. If the", 0Dh, 0Ah
                                 DB " exception is instead caught by a debugger, the expected control flow", 0Dh, 0Ah
                                 DB " will be altered.", 0Dh, 0Ah, 0h

szHardwareBreakpointDetectionTitle DB "Hardware Breakpoint Detection ", 0Dh, 0Ah, 0h
szHardwareBreakpointDetectionRef   DB "Reference: PF-TUADR - 6.A", 0Dh, 0Ah, 0h
szHardwareBreakpointDetectionText  DB " Out of the eight debug registers (DR), four can be used to set addresses which", 0Dh, 0Ah
                                   DB " will trigger a break when they are loaded into the EIP register.", 0Dh, 0Ah
                                   DB " Those are called debug address registers, DR0 - DR3. The registers ", 0Dh, 0Ah
                                   DB " themselves are a privileged (ring0) resource and not directly accessible.", 0Dh, 0Ah
                                   DB " Therefore, in this test we generate an exception in order to retrieve the ", 0Dh, 0Ah
                                   DB " values. Those are then compared to zero, which is their initial ", 0Dh, 0Ah
                                   DB " value. If they are not equal zero, a hardware breakpoint is set and this ", 0Dh, 0Ah
                                   DB " indicates a debugger is running.", 0Dh, 0Ah, 0h

szSoftICE3hTitle DB "SoftICE 3h", 0Dh, 0Ah, 0h
szSoftICE3hRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szSoftICE3hText  DB " If SoftICE is active, an INT 0x3 breakpoint is set at the beginning of the", 0Dh, 0Ah
                 DB " API function kernel32.UnhandledExceptionFilter(). This test inspects the", 0Dh, 0Ah
                 DB " start address of this function for the presence of an INT 0x3 (0xCC).", 0Dh, 0Ah, 0h

szFLDKillOllyDbgTitle DB "Kill OllyDbg 1.10 with a crafted floating point value", 0Dh, 0Ah, 0h
szFLDKillOllyDbgRef   DB "Reference: PF-TUADR - 7.F.i", 0Dh, 0Ah, 0h
szFLDKillOllyDbgText  DB " The code analyzer of OllyDbg 1.10 contains a bug in handling floating-point", 0Dh, 0Ah
                      DB " conversions. When the two values +/-9.2233720368547758075e18 are converted", 0Dh, 0Ah
                      DB " from double-extension to integer, OllyDbg crashes.", 0Dh, 0Ah, 0h

szCRCBreakpointTitle DB "CRC Breakpoint", 0Dh, 0Ah, 0h
szCRCBreakpointRef   DB "Reference: OpenRCE", 0Dh, 0Ah, 0h
szCRCBreakpointText  DB " When a process is being debugged and breakpoints are set up, code in memory is", 0Dh, 0Ah
                     DB " modified by dynamically replacing instructions with INT 0x3 instructions.", 0Dh, 0Ah
                     DB " This CRC routine checks the checksum of the known compiled code against", 0Dh, 0Ah
                     DB " the current in-memory version and detects changes through a changed checksum.", 0Dh, 0Ah, 0h

szCreateFileTitle DB "Create File", 0Dh, 0Ah, 0h
szCreateFileRef   DB "Reference: PF-TUADR - 7.B.iii", 0Dh, 0Ah, 0h
szCreateFileText  DB " The technique of this test is based on trying to open the file of the current", 0Dh, 0Ah
                  DB " process with kernel32.CreateFile() for exclusive access. Usually, if a process", 0Dh, 0Ah
                  DB " is started as debugged, a handle to the file is opened allowing the debugger", 0Dh, 0Ah
                  DB " to read the debugging information if present. If this handle is not closed", 0Dh, 0Ah
                  DB " by the debugger, the request for exclusive access fails. However, this method", 0Dh, 0Ah
                  DB " is only of limited reliability for detecting a debugger because another tool", 0Dh, 0Ah
                  DB " e.g. an editor may have already opened it.", 0Dh, 0Ah, 0h

szRaiseExceptionTitle DB "kernel32.RaiseException()", 0Dh, 0Ah, 0h
szRaiseExceptionRef   DB "Reference: PF-TUADR - 7.G.ix", 0Dh, 0Ah, 0h
szRaiseExceptionText  DB " The kernel32.RaiseException() function can be used to force a specified", 0Dh, 0Ah
                      DB " exception to occur. This includes exceptions that a debugger consumes during", 0Dh, 0Ah
                      DB " execution. When raised during debugging, exceptions like DBC_CONTROL_C", 0Dh, 0Ah
                      DB " or DBG_RIPEVENT are usually not forwarded to the process after ", 0Dh, 0Ah
                      DB " consumption, thus allowing detection of presence of a debugger.", 0Dh, 0Ah, 0h

szLoadLibraryTitle DB "kernel32.LoadLibrary()", 0Dh, 0Ah, 0h
szLoadLibraryRef   DB "Reference: PF-TUADR - 7.B.iv", 0Dh, 0Ah, 0h
szLoadLibraryText  DB " This test works at least against Immunity and Olly 1.1.", 0Dh, 0Ah
                   DB " The idea is that loading a file with the API call kernel32.LoadLibrary()", 0Dh, 0Ah
                   DB " in the presence of a debugger and freeing again with kernel32.FreeLibrary(),", 0Dh, 0Ah
                   DB " causes a handle to remain open for this file. As a result, the file ", 0Dh, 0Ah
                   DB " can no longer be opened for exclusive access. The test works similar to ", 0Dh, 0Ah
                   DB " CreateFile method and can be used to infer the presence of a debugger.", 0Dh, 0Ah, 0h

szInt2dTitle DB "Int 2d", 0Dh, 0Ah, 0h
szInt2dRef   DB "Reference: PF-TUADR - 6.D", 0Dh, 0Ah, 0h
szInt2dText  DB " The interrupt 0x2d provides various means of creating certain behaviour,", 0Dh, 0Ah
             DB " depending on the debuggers implementation of exception handling and the", 0Dh, 0Ah
             DB " value in the EAX register. In the normal case, Windows uses the current EIP", 0Dh, 0Ah
             DB " as causing address for a EXCEPTION_BREAKPOINT exception (if a debugger is ", 0Dh, 0Ah
             DB " present), continuing with the following instruction. In case EAX has ", 0Dh, 0Ah
             DB " the value 1, 3, 4 (or 5 for Vista and above), EIP is incremented by 1,", 0Dh, 0Ah
             DB " resulting in the case that one byte immediately after the int 2d instruction", 0Dh, 0Ah
             DB " is skipped. This byte-skip can be used for code-obfuscation or inferring", 0Dh, 0Ah
             DB " the presence of a debugger.", 0Dh, 0Ah, 0h

szToolHelp32ReadProcessMemoryTitle DB "kernel32.ToolHelp32ReadProcessMemory - Breakpoint Detection", 0Dh, 0Ah, 0h
szToolHelp32ReadProcessMemoryRef   DB "Reference: PF-TUADR - 7.D.xiii", 0Dh, 0Ah, 0h
szToolHelp32ReadProcessMemoryText  DB " This is a modified variant (read-only) of the technique for rewriting the ", 0Dh, 0Ah
                                   DB " debugger's breakpoint on the next instruction (PF-TUADR - 5).", 0Dh, 0Ah
                                   DB " The test makes use of the kernel32.ToolHelp32ReadProcessMemory API call", 0Dh, 0Ah
                                   DB " to read the byte following the call and compares it to 0xCC (int 3),", 0Dh, 0Ah
                                   DB " the instruction used by debuggers for setting a software breakpoint.", 0Dh, 0Ah, 0h

szCtrlCTitle DB "Ctrl + C", 0Dh, 0Ah, 0h
szCtrlCRef   DB "Reference: PF-TUADR - 7.G.v", 0Dh, 0Ah, 0h
szCtrlCText  DB " The idea of this test is to emit the shortcut Ctrl + C, which results in an", 0Dh, 0Ah
             DB " exception if the process is being debugged. We can catch this exception in", 0Dh, 0Ah
             DB " our SEH exception handler to infer presence of a debugger.", 0Dh, 0Ah, 0h

szCallPopTitle DB "GetIP via Call/Pop Sequence", 0Dh, 0Ah, 0h
szCallPopRef   DB "Reference: Corkami", 0Dh, 0Ah, 0h
szCallPopText  DB " This is not a debugging detection, but a technique used in shellcode", 0Dh, 0Ah
               DB " to infer the current instruction pointer. By using a CALL instruction", 0Dh, 0Ah
               DB " with argument 0 (thus calling the instruction directly following the CALL)", 0Dh, 0Ah
               DB " and a POP, the value of EIP is acquired.", 0Dh, 0Ah, 0h

szSehGetIpTitle DB "GetIP via SEH", 0Dh, 0Ah, 0h
szSehGetIpRef   DB "Reference: Corkami", 0Dh, 0Ah, 0h
szSehGetIpText  DB " Another way to obtain the current instruction pointer is through examination", 0Dh, 0Ah
                DB " of an ExceptionRecord. To produce such a structure, first a SEH is set up.", 0Dh, 0Ah
                DB " Next, an exception is forced, in our example simply through dividing by zero.", 0Dh, 0Ah
                DB " Finally, the address of the instruction that caused the exception is extracted", 0Dh, 0Ah
                DB " from the exception record that has been created on the stack.", 0Dh, 0Ah, 0h

szInt2eTitle DB "GetIP via INT 2e / 2c", 0Dh, 0Ah, 0h
szInt2eRef   DB "Anti-Unpacker Tricks - Part Seven & Fourteen (Peter Ferrie)", 0Dh, 0Ah, 0h
szInt2eText  DB " In the case that the CPU supports the SYSEXIT instruction, INT 2e can be", 0Dh, 0Ah
             DB " used to obtain the address of the following instruction. This is caused", 0Dh, 0Ah
             DB " by a side effect that occurs through address adjustments performed in the", 0Dh, 0Ah
             DB " kernel to use SYSEXIT instead of IRETD, this way putting EIP in EDX ", 0Dh, 0Ah
             DB " register.", 0Dh, 0Ah
             DB " In the context of Anti-Debugging, it is acknowledgable that SYSEXIT is", 0Dh, 0Ah
             DB " not supported by older versions of some virtualization software and EDX", 0Dh, 0Ah
             DB " will hold a value else then EIP after execution of INT 2e. This can be", 0Dh, 0Ah
             DB " tested and thus be used as detection mechanism.", 0Dh, 0Ah, 0h

szFPUTitle DB "GetIP via FPU", 0Dh, 0Ah, 0h
szFPURef   DB "Reference: Corkami / Shellgames (Peter Ferrie)", 0Dh, 0Ah, 0h
szFPUText  DB " In this variant, the current EIP is obtained through the use of", 0Dh, 0Ah
           DB " floating point instructions. For this, we can use a subset of FPU", 0Dh, 0Ah
           DB " opcodes (all except FNCLEX, FLDCW, FNSTCW, FNSTSW, FNSTENV, FLDENV,", 0Dh, 0Ah
           DB " FN/XSAVE, F[X]RSTOR), in this case FNOP, and then store the FPU", 0Dh, 0Ah
           DB " environment in memory via F(N)STENV. This test will not work", 0Dh, 0Ah
           DB " correctly if executed by stepping through the commands, thus", 0Dh, 0Ah
           DB " serving as anti-stepping mechanism.", 0Dh, 0Ah, 0h

szAntiSteppingTitle DB "AntiStepping", 0Dh, 0Ah, 0h
szAntiSteppingRef   DB "Reference: PF-TUADR - 7.E.iv", 0Dh, 0Ah, 0h
szAntiSteppingText  DB " In this anti-stepping test we change the value of the GS segment", 0Dh, 0Ah
                    DB " register. The content of this register will be reset to zero after", 0Dh, 0Ah
                    DB " a thread context switch. If we set the value and read from the register", 0Dh, 0Ah
                    DB " immediately, the modified value will usually retain. In the case of", 0Dh, 0Ah
                    DB " stepping, the value will be reset to zero as mentioned.", 0Dh, 0Ah
                    DB " To exclude the case of falling to a race condition, we first loop", 0Dh, 0Ah
                    DB " while checking if the value is still 3. Directly after it has been", 0Dh, 0Ah
                    DB " reset because of a context switch, we set it again to 3 and check it", 0Dh, 0Ah
                    DB " again to determine whether it has persisted in this short time or not.", 0Dh, 0Ah, 0h

szMovSSTitle DB "MOV SS", 0Dh, 0Ah, 0h
szMovSSRef   DB "Reference: PF-TUADR - 6.F", 0Dh, 0Ah, 0h
szMovSSText  DB " This test is used to detect single-stepping. It works since the days of", 0Dh, 0Ah
             DB " DOS and is still working in all versions of Windows (32-bit and 64-bit).", 0Dh, 0Ah
             DB " Normally when you execute the pushfd instruction to get the EFflags, debuggers", 0Dh, 0Ah
             DB " like Olly conceal themself by cleaning the result especially the trap flag.", 0Dh, 0Ah
             DB " But POP SS disables all interrupts (like the NMI interrupt) until ", 0Dh, 0Ah
             DB " the end of the next instruction, so the debugger will never know the", 0Dh, 0Ah
             DB " next instruction (pushfd) is executed and cannot clean the trap flag.", 0Dh, 0Ah, 0h

szRewriteAntiSteppingTitle DB "AntiStepping by Rewriting the Debugger's Breakpoint", 0Dh, 0Ah, 0h
szRewriteAntiSteppingRef   DB "Reference: PF-TUADR - 5", 0Dh, 0Ah, 0h
szRewriteAntiSteppingText  DB " Debuggers usually set a software breakpoint (0xCC) on the next ", 0Dh, 0Ah
                           DB " instruction to realize single stepping. This code uses an ", 0Dh, 0Ah
                           DB " instruction to rewrite the first byte of the following instruction", 0Dh, 0Ah
                           DB " in order to nullify this breakpoint. The effect is that the ", 0Dh, 0Ah
                           DB " debugger loses track of the stepping and the application", 0Dh, 0Ah
                           DB " continues its execution without stepping.", 0Dh, 0Ah, 0h

szSehTitle DB "Triggering Exceptions", 0Dh, 0Ah, 0h
szSehRef   DB "Reference: Corkami", 0Dh, 0Ah, 0h
szSehText  DB " In this test we use different instructions to illustrate that exceptions", 0Dh, 0Ah
           DB " trigger at different times and thus point to addresses chosen after context.", 0Dh, 0Ah
           DB " For example, most exceptions (in this case writing to a null pointer) will", 0Dh, 0Ah
           DB " trigger before executing the instruction in question, pointing to the address", 0Dh, 0Ah
           DB " of the statement causing the exception. Others will trigger after", 0Dh, 0Ah
           DB " execution (IceBB), and some will even trigger delayed by one", 0Dh, 0Ah
           DB " instruction (through manipulation of flags) to enable stepping.", 0Dh, 0Ah, 0h

szDeleteFiberTitle DB "kernel32.DeleteFiber() -> kernel32.GetLastError()", 0Dh, 0Ah, 0h
szDeleteFiberRef   DB "Reference: Corkami", 0Dh, 0Ah, 0h
szDeleteFiberText  DB " This test triggers a debugging exception by calling the kernel32.DeleteFiber()", 0Dh, 0Ah
                   DB " function. If no debugger is present, the return code will be equal to", 0Dh, 0Ah
                   DB " 0x57 (ERROR_INVALID_PARAMETER) and if a debugger is present it will", 0Dh, 0Ah
                   DB " have a different value. Works not on Vista+.", 0Dh, 0Ah, 0h

szCloseHandleTitle DB "kernel32.CloseHandle()", 0Dh, 0Ah, 0h
szCloseHandleRef   DB "Reference: PF-TUADR - 7.B.ii", 0Dh, 0Ah, 0h
szCloseHandleText  DB " This test is another way to use special exception handling mechanisms in", 0Dh, 0Ah
                   DB " case of debugger presence. By calling kernel32.CloseHandle() on an invalid", 0Dh, 0Ah
                   DB " handle an EXCEPTION_INVALID_HANDLE (0xC0000008) exception is raised. ", 0Dh, 0Ah
                   DB " By setting up an exception handler previous to calling the function, the ", 0Dh, 0Ah
                   DB " exception can be caught which is an indication of debugger presence.", 0Dh, 0Ah
                   DB " If there is no debugger present, execution continues unaffected.", 0Dh, 0Ah, 0h

szInt41Title DB "Int 41", 0Dh, 0Ah, 0h
szInt41Ref   DB "Reference: PF-TUADR - 6.E", 0Dh, 0Ah, 0h
szInt41Text  DB " This test uses the interrupt 41h which may show different behaviour", 0Dh, 0Ah
             DB " if a kernel-mode debugger is present. Normally it cannot be executed", 0Dh, 0Ah
             DB " from ring 3 (it has a DPL of zero), but some debuggers hook this interrupt", 0Dh, 0Ah
             DB " and it can be executed from user mode.", 0Dh, 0Ah, 0h

szDebugInheritTitle DB "Flags: Debug Inherit", 0Dh, 0Ah, 0h
szDebugInheritRef   DB "Reference: PF-TUADR - 7.D.viii", 0Dh, 0Ah, 0h
szDebugInheritText  DB " The argument ProcessDebugFlags (01Fh) is a parameter that can be passed to", 0Dh, 0Ah
                    DB " the ntdll.NtQueryInformationProcess(). When this function is called with", 0Dh, 0Ah
                    DB " ProcessDebugFlags, it'll return the inverse of EPROCESS->NtDebugInherit.", 0Dh, 0Ah
                    DB " If a debugger is working on our process FALSE (0h) is returned.", 0Dh, 0Ah, 0h

szDebugObjectHandleTitle DB "Flags: Debug Object Handle", 0Dh, 0Ah, 0h
szDebugObjectHandleRef   DB "Reference: PF-TUADR - 7.D.viii", 0Dh, 0Ah, 0h
szDebugObjectHandleText  DB " IThis test is similar to the Debug Inherit Test. But in this case the", 0Dh, 0Ah
                         DB " ntdll.NtQueryInformationProcess() is called with ", 0Dh, 0Ah
                         DB " ProcessDebugObjectHandle (01Eh). This call returns a handle of our process", 0Dh, 0Ah
                         DB " in the case it is being debugged.", 0Dh, 0Ah, 0h

szParentProcessIdTitle DB "Checking the ParentProcessId", 0Dh, 0Ah, 0h
szParentProcessIdRef   DB "Reference: PF-TUADR - 7.D.ii", 0Dh, 0Ah, 0h
szParentProcessIdText  DB " In this test we take a look at the ParentProcessId. If our program has", 0Dh, 0Ah
                       DB " been started from e.g. the Desktop explorer.exe is the parent. If our program", 0Dh, 0Ah
                       DB " has been started from a debugger, the debugger is our process's parent. At", 0Dh, 0Ah
                       DB " first we use the API call user32.GetWindowThreadProcessId() to get the PID of", 0Dh, 0Ah
                       DB " explorer.exe, then we get the ParentProcessId of our process by calling ", 0Dh, 0Ah
                       DB " NtQueryInformationProcess. This way we can compare them for equality. However,", 0Dh, 0Ah
                       DB " this won't work if this tool is started from the commandline but the concept", 0Dh, 0Ah
                       DB " should be clear though.", 0Dh, 0Ah, 0h

szSetLastErrorTitle DB "kernel32.SetLastError()", 0Dh, 0Ah, 0h
szSetLastErrorRef   DB "Reference: PF-TUADR - 7.D.ix", 0Dh, 0Ah, 0h
szSetLastErrorText  DB " In this test Last Error is set to 0C0000005h (ACCESS_VIOLATION) by calling.", 0Dh, 0Ah
                    DB " the API function SetLastError. After that we try to output a debug string.", 0Dh, 0Ah
                    DB " If a debugger is attached, this will likely not change the LastError,", 0Dh, 0Ah
                    DB " but if no debugger is attached, it should evaluate to ERROR_FILE_NOT_FOUND", 0Dh, 0Ah
                    DB " If OllyDbg 1.1 is attached to this process it will likely crash due to", 0Dh, 0Ah
                    DB " the choosen output string (%%s%%s). This is caused by a bug in OllyDbg 1.1", 0Dh, 0Ah
                    DB " and serves as a bonus in this test.", 0Dh, 0Ah, 0h

szWindowsVistaDebuggerTitle DB "Windows Vista Debugger", 0Dh, 0Ah, 0h
szWindowsVistaDebuggerRef   DB " Reference: Symantec (Nicolas Falliere)", 0Dh, 0Ah, 0h
szWindowsVistaDebuggerText  DB " On Windows Vista (32bit), debugging a process affects a certain memory", 0Dh, 0Ah
                            DB " location in the main Thread Environment Block. Specifically, 0xBFC will", 0Dh, 0Ah
                            DB " point to a unicode string of a system DLL. The string is directly", 0Dh, 0Ah
                            DB " located at 0xC00 in the main TEB, thus following the pointer. If the", 0Dh, 0Ah
                            DB " process is not debugged, the pointer at 0xBFC is NULL. This can be used", 0Dh, 0Ah
                            DB " to detect the presence of a debugger.", 0Dh, 0Ah, 0h

szInt2eRedirectTitle   DB "Control Flow Redirection through INT 2e", 0Dh, 0Ah, 0h
szInt2eRedirectRef     DB "Reference: Anti-Unpacker Tricks - Part Fourteen (Peter Ferrie)", 0Dh, 0Ah, 0h
szInt2eRedirectText    DB " On 32bit Windows Vista and Windows 7 the INT 2e can be used to redirect", 0Dh, 0Ah
                       DB " control flow. When using the interrupt with an value of EAX exceeding the", 0Dh, 0Ah
                       DB " size of the standard service table, a call through ", 0Dh, 0Ah
                       DB " ntdll.KiUserCallbackDispatcher() using the Kernel Callback Table (which", 0Dh, 0Ah
                       DB " is referenced by the PEB) is issued. The target address of this call has", 0Dh, 0Ah
                       DB " an offset of 0x4a (Vista) or 0x4c (Win 7) in the callback table as", 0Dh, 0Ah
                       DB " referenced via PEB. A debugger not aware of this fact can lose track", 0Dh, 0Ah
                       DB " when stepping over the interrupt.", 0Dh, 0Ah, 0h

szSetInformationThreadTitle DB "Set Information Thread", 0Dh, 0Ah, 0h
szSetInformationThreadRef   DB "Reference: PF-TUADR - 7.F.iii", 0Dh, 0Ah, 0h
szSetInformationThreadText  DB " Using kernel32.SetInformationThread with the HideThreadFromDebugger enabled", 0Dh, 0Ah
                            DB " will cause a Debugger to lose track of the current thread", 0Dh, 0Ah, 0h

szCanOpenCsrssTitle DB "Can open process Csrss.exe", 0Dh, 0Ah, 0h
szCanOpenCsrssRef   DB "Reference: PF-TUADR - 7.B.i", 0Dh, 0Ah, 0h
szCanOpenCsrssText  DB " In this test, the PID of csrss.exe is acquired through", 0Dh, 0Ah
                    DB " ntdll.CsrGetProcessId(). Next, kernel32.OpenProcess is used on this PID", 0Dh, 0Ah
                    DB " with PROCESS_ALL_ACCESS attribute. This will only succeed in the case", 0Dh, 0Ah
                    DB " that the requesting process has SeDebugPrivilege enabled, which means", 0Dh, 0Ah
                    DB " it is running with highest privileges. This might be caused by a", 0Dh, 0Ah
                    DB " debugger. From a general perspective, this test has to be taken as", 0Dh, 0Ah
                    DB " unreliable.", 0Dh, 0Ah, 0h

szThreadLocalStorageTitle DB "Thread Local Storage Callbacks", 0Dh, 0Ah, 0h
szThreadLocalStorageRef   DB " Reference: PF-TUADR - 4", 0Dh, 0Ah, 0h
szThreadLocalStorageText  DB " Thread Local Storage (TLS) is originally intended to allow the", 0Dh, 0Ah
                          DB " initialization of data for certain threads. As every process contains", 0Dh, 0Ah
                          DB " at least the main thread and have to be executed before this thread is", 0Dh, 0Ah
                          DB " started, it can be used as a measure to execute code prior to the entry", 0Dh, 0Ah
                          DB " point. An interesting situation occurs when a debugger attaches to a", 0Dh, 0Ah
                          DB " running program. Debugger threads have an entry point that lies not in", 0Dh, 0Ah
                          DB " the PE image but in kernel32.dll. This can be checked from within a", 0Dh, 0Ah
                          DB " TLS callback and thus before the debugger gains control over the", 0Dh, 0Ah
                          DB " process.", 0Dh, 0Ah, 0h

szCreateToolhelp32SnapshotTitle DB "CreateToolhelp32Snapshot", 0Dh, 0Ah, 0h
szCreateToolhelp32SnapshotRef   DB "Reference: PF-TUADR - 7.D.iii", 0Dh, 0Ah, 0h
szCreateToolhelp32SnapshotText  DB " This test tries to identify the parent process of the current process.", 0Dh, 0Ah
                                DB " By using the kernel32.dll function CreateToolhelp32Snapshot to capture", 0Dh, 0Ah
                                DB " all current processes and iterating with Process32Next through the", 0Dh, 0Ah
                                DB " generated list, the process id of explorer.exe (assuming this program", 0Dh, 0Ah
                                DB " was started directly by a double click) can be obtained. If this PID", 0Dh, 0Ah
                                DB " matches the of this process, it is less likely that is was started by", 0Dh, 0Ah
                                DB " a debugger or other analysis tool.", 0Dh, 0Ah, 0h

szBlockInputTitle DB "user32.BlockInput(True)", 0Dh, 0Ah, 0h
szBlockInputRef   DB "Reference: PF-TUADR - 7.F.i", 0Dh, 0Ah, 0h
szBlockInputText  DB " If user32.BlockInput(True) is called, it will block any mouse and keyboard",  0Dh, 0Ah
                  DB " input for our process, thus messing up the debugger if controlled by a human", 0Dh, 0Ah, 0h

szDynamicLargeSizeOfImageTitle DB "AntiDump: Increase size of image dynamically", 0Dh, 0Ah, 0h
szDynamicLargeSizeOfImageRef   DB "Reference: Joshua Jackson AntiRE Library", 0Dh, 0Ah, 0h
szDynamicLargeSizeOfImageText  DB " This technique increases the SizeOfImage field in the Process Environment",  0Dh, 0Ah
                               DB " Blocks to a very large value. This way, an attaching debugger or dumper",  0Dh, 0Ah
                               DB " may try to allocate far more memory than necessary and fail to work.", 0Dh, 0Ah
                               DB " For example, LordPE cannot grab process memory after executing this test.", 0Dh, 0Ah, 0h

szVmSldtTitle DB "VM Detection: SLDT", 0Dh, 0Ah, 0h
szVmSldtRef   DB "Reference: Attacks on Virtual Machine Emulators (Peter Ferrie)", 0Dh, 0Ah, 0h
szVmSldtText  DB " This technique reads the memory address of the Local Descriptor Table.", 0Dh, 0Ah
              DB " For a native system and newer versions of VirtualBox, this value is 00 00, ", 0Dh, 0Ah
              DB " while on other virtual environments it will deviate from zero. In this case", 0Dh, 0Ah
              DB " it indicates the presence of virtualization.", 0Dh, 0Ah, 0h

szVmSidtTitle DB "VM Detection: SIDT", 0Dh, 0Ah, 0h
szVmSidtRef   DB "Reference: Attacks on Virtual Machine Emulators (Peter Ferrie)", 0Dh, 0Ah, 0h
szVmSidtText  DB " This technique reads the memory address of the Interrupt Descriptor Table.", 0Dh, 0Ah
              DB " The address is set by the operating system and must be unique for the OS", 0Dh, 0Ah
              DB " and the processor. If there are two operating systems running on the same cpu,", 0Dh, 0Ah
              DB " one OS has two use an unusual address. In case of the IDT, a value greater or", 0Dh, 0Ah
              DB " equal to 0xD0 for the highest byte indicates a virtual machine.", 0Dh, 0Ah, 0h

szVmSgdtTitle DB "VM Detection: SGDT", 0Dh, 0Ah, 0h
szVmSgdtRef   DB "Reference: Attacks on Virtual Machine Emulators (Peter Ferrie)", 0Dh, 0Ah, 0h
szVmSgdtText  DB " This tests uses the Global Descriptor Table for finding a Virtual Machine.", 0Dh, 0Ah
              DB " The approach is exactly the same like in the SIDT test.", 0Dh, 0Ah, 0h

szVmMagicNumberVMwareTitle DB "VM Detection: Magic Number (VMware)", 0Dh, 0Ah, 0h
szVmMagicNumberVMwareRef   DB "Reference: Attacks on Virtual Machine Emulators (Peter Ferrie)", 0Dh, 0Ah, 0h
szVmMagicNumberVMwareText  DB " The VMware Software uses a special I/O-Port for the communication between the", 0Dh, 0Ah
                           DB " Virtual Machine and the Host Software. Using this port you can also get", 0Dh, 0Ah
                           DB " information about the VMware version. To get the version number 'VMXh' is", 0Dh, 0Ah
                           DB " put in eax, 0 in ebx, 10 in ecx and 'VXh' in edx. A interrupt is triggered", 0Dh, 0Ah
                           DB " and by finding 'VMXh' in ebx, VMware is detected.", 0Dh, 0Ah, 0h

szVmMagicNumberParallelsTitle DB "VM Detection: Magic Number (Parallels)", 0Dh, 0Ah, 0h
szVmMagicNumberParallelsRef   DB "Reference: Jaelani's Just Another Vm Detection", 0Dh, 0Ah
                              DB "http://my.opera.com/jaelanicu/blog/", 0Dh, 0Ah
                              DB "just-another-vm-detection-was-vm-detection-combo", 0Dh, 0Ah, 0h
szVmMagicNumberParallelsText  DB " This test works like the VMware test. It detects Parallels, that's why", 0Dh, 0Ah
                              DB " it uses slightly different values in the registers.", 0Dh, 0Ah, 0h

szVmMagicNumberVirtualPcTitle DB "VM Detection: Magic Number (VirtualPC)", 0Dh, 0Ah, 0h
szVmMagicNumberVirtualPcRef   DB "Reference: Attacks on Virtual Machine Emulators (Peter Ferrie)", 0Dh, 0Ah, 0h
szVmMagicNumberVirtualPcText  DB " This test demonstrates behaviour of two instructions (0F 3F x1 x2;", 0Dh, 0Ah
                              DB " 0F C7 C8 y1 y2) that cause an exception on a native machine but are", 0Dh, 0Ah
                              DB " recognized by VirtualPC. (x1 x2) is set to (07 0B) and (y1 y2) is set", 0Dh, 0Ah
                              DB " to (01 00), both combinations are an encoding for the", 0Dh, 0Ah
                              DB " IsRunningInsideVirtualMachine() API of VirtualPC. More values are", 0Dh, 0Ah
                              DB " supported by VirtualPC, these are explained in detail in the referenced", 0Dh, 0Ah
                              DB " paper. Executing the instructions allows detection through setting up a", 0Dh, 0Ah
                              DB " SEH and checking if the instructions cause an exception.", 0Dh, 0Ah, 0h

szRtlQueryProcessHeapInformationTitle  DB "RtlQueryProcessHeapInformation", 0Dh, 0Ah, 0h
szRtlQueryProcessHeapInformationRef    DB " Reference: PF-TUADR - 7.D.x", 0Dh, 0Ah, 0h
szRtlQueryProcessHeapInformationText   DB " This API call returns heap flags for the current process. The flags", 0Dh, 0Ah
                                       DB " can be checked for typical values set for debugging, like", 0Dh, 0Ah
                                       DB " growable heap, tail and free checking enabled. It is limited to", 0Dh, 0Ah
                                       DB " versions of Windows prior to Vista.", 0Dh, 0Ah, 0h

szRtlQueryProcessDebugInformationTitle  DB "RtlQueryProcessDebugInformation", 0Dh, 0Ah, 0h
szRtlQueryProcessDebugInformationRef    DB " Reference: PF-TUADR - 7.D.xi", 0Dh, 0Ah, 0h
szRtlQueryProcessDebugInformationText   DB " This test is similar to the heap flag evaulation of", 0Dh, 0Ah
                                        DB " RtlQueryProcessHeapInformation, as this function is", 0Dh, 0Ah
                                        DB " used internally by RtlQueryProcessDebugInformation.", 0Dh, 0Ah
                                        DB " It is also limited to versions prior to Vista.", 0Dh, 0Ah, 0h

szTimingEmulationTitle DB "Anti emulation test based on execution timing", 0Dh, 0Ah, 0h
szTimingEmulationRef DB " Reference: -", 0Dh, 0Ah, 0h
szTimingEmulationText DB " This test is based on combining execution timing as before with assumptions", 0Dh, 0Ah 
                      DB " on the behaviour of an analysis environment. Some analysis environments", 0Dh, 0Ah
                      DB " intercept calls to execution delaying methods such as calls to", 0Dh, 0Ah
                      DB " kernel32.Sleep() and reduce the original wait time to a minimum. By", 0Dh, 0Ah
                      DB " surrounding the Sleep() call with time measurements, we ensure that the", 0Dh, 0Ah
                      DB " intended time was paused and assume an emulation environment otherwise.", 0Dh, 0Ah, 0h
      
; TODO          
szInstructionCountingTitle DB "Exception-based instruction counting", 0Dh, 0Ah, 0h
szInstructionCountingRef   DB " Reference: PF-TUADR - 6.B", 0Dh, 0Ah, 0h
szInstructionCountingText  DB " Basis for this test is the way the target analysis environment treats", 0Dh, 0Ah
                           DB " single step and breakpoint exceptions. First, a custom SEH is registered.", 0Dh, 0Ah
                           DB " Once it has been hit, the handler sets hardware breakpoints via context", 0Dh, 0Ah
                           DB " manipulation on the following instructions. Each of these causes a counter", 0Dh, 0Ah
                           DB " to be incremented that is returned in EAX. After having created and counted", 0Dh, 0Ah
                           DB " 4 breakpoint exceptions this counter is checked and depending on the result,", 0Dh, 0Ah
                           DB " it is inferred whether or not an analysis environment is present.", 0Dh, 0Ah, 0h


szSetup             DB "Setup: The following function parses the commandline arguments and sets the .text section writable.", 0h
szMakeWritable      DB "Grant .text section RWX access.", 0h
szParseArgs         DB "Parse commandline arguments", 0h



; #### Group titles and data related to program control ###################

szGroupDivider      DB "==============================================================================", 0Dh, 0Ah, 0h
groupTitleIntro     DB "Next Group of Techniques: ", 0h
szGroupTimingTests  DB "Timing Tests", 0Dh, 0Ah, 0h
szGroupFlags        DB "Flags", 0Dh, 0Ah, 0h
szGroupAntiStepping DB "Anti-Stepping", 0Dh, 0Ah, 0h
szGroupApiCall      DB "API Calls", 0Dh, 0Ah, 0h
szGroupDebuggers    DB "Debugger Specific Techniques", 0Dh, 0Ah, 0h
szGroupExceptions   DB "Exception-based Techniques", 0Dh, 0Ah, 0h
szGroupIntegrity    DB "Integrity Checks", 0Dh, 0Ah, 0h
szGroupErrorCodes   DB "Error Code-based Techniques", 0Dh, 0Ah, 0h
szGroupOsDependant  DB "Operating System limited Techniques", 0Dh, 0Ah, 0h
szGroupNtQIP        DB "ntdll.NtQueryInformationProcess", 0Dh, 0Ah, 0h
szGroupMisc         DB "Miscellanous Tests", 0Dh, 0Ah, 0h
szGroupVM           DB "Detection of Virtual Machines", 0Dh, 0Ah, 0h
szGroupGetIp        DB "GetInstructionPointer (GetIp) Routines", 0Dh, 0Ah, 0h
szGroupLeftOver     DB "Left-Overs (breaking proper execution)", 0Dh, 0Ah, 0h
szResults           DB "Test Results", 0Dh, 0Ah, 0h
szTestDivider       DB "------------------------------------------------------------------------------", 0Dh, 0Ah, 0h

szNewLine      DB 0Dh, 0Ah, 0h
szTestText     DB "Test ", 0h
szStartText    DB "Press <anykey> to start", 0Dh, 0Ah, 0Dh, 0Ah, 0h
szExitText     DB "Press <anykey> to exit program", 0Dh, 0Ah, 0Dh, 0Ah, 0h
szContinueText DB "Press <anykey> to continue", 0Dh, 0Ah, 0Dh, 0Ah, 0h

szTestSuccessfulMessage    DB "    Ok (no debugger / analysis environment found)", 0Dh, 0Ah, 0h
szTestFailedMessage        DB "    Failed (debugger / analysis environment found)", 0Dh, 0Ah, 0h
szTestAbortedMessage       DB "    Aborted (due to unfulfilled conditions)", 0Dh, 0Ah, 0h
szSubtestSuccessfulMessage DB "    Ok (Exception naturally handled)", 0Dh, 0Ah, 0h
szSubtestFailedMessage     DB "    Failed", 0Dh, 0Ah, 0h

szFinishText     DB "All tests finished!", 0Dh, 0Ah, 0h
szSuccessfulText DB "Successful Tests: ", 0h
szFailedText     DB "Failed Tests: ", 0h

szIpAddress        DB "    Instruction Pointer Address: ", 0h
szCRCresult        DB "    Result of CRC calculation: ", 0h
szSetLastErrorCode DB "    Last Error: ", 0h

szReportFormatInt   DB "%i: ", 0h
szReportFormatIntWW DB "%i", 0Dh, 0Ah, 0h
szReportFormatHexWW DB "0x%08x", 0Dh, 0Ah, 0h

szBackSlash         DB "\", 0h

szArgumentA         DB "-a", 0h
szArgumentO         DB "-o", 0h
szOutputFilename    DB "anti_re_output.log", 0h

setup_done           DD 0h
execute_tls_test     DD 0h
hReportOutputFile    DD 0h
dwTestCounter        DD 0h
dwSuccessCounter     DD 0h
dwFailCounter        DD 0h
dwSehTestFailCounter DD 0h
dwTemporary          DD 0h
dwIpAddress          DD 0h
dwCRC32result        DD 0h



; #### Strings and constants used by tests ################################

szNtdll                    DB "ntdll.dll", 0h
szKernel32Dll              DB "kernel32.dll", 0h
szWs2_32Dll                DB "C:\Windows\system32\ws2_32.dll", 0h
szIsWow64Process           DB "IsWow64Process", 0h
szOpenProcess              DB "OpenProcess", 0h

szSetLastErrorDebugString  DB "%s%s", 0h

szOllyKey   DB "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug", 0h
szIsOllyKey DB "Debugger", 0h
szREGSZ     DB "REG_SZ", 0h
szIsSICEKey DB "InstallDir", 0h

szOllyDbgFindWindow         DB "OLLYDBG", 0Dh, 0Ah, 0h
szOllyDbgFindShadowWindow   DB "SHADOW", 0Dh, 0Ah, 0h

szSICEKey   DB "SOFTWARE\NuMega\DriverStudio", 0h
szWinICE    DB "\system32\drivers\WinICE.dat", 0h

szAnalysisTool_0  DB "\\.\EXTREM", 0h                ; Phant0m
szAnalysisTool_1  DB "\\.\FILEVXG", 0h               ; FileMon
szAnalysisTool_2  DB "\\.\FILEM", 0h                 ; FileMon
szAnalysisTool_3  DB "\\.\ICEEXT", 0h                ; SoftICE Extender
szAnalysisTool_4  DB "\\.\NDBGMSG.VXD", 0h           ; SoftICE
szAnalysisTool_5  DB "\\.\NTICE", 0h                 ; SoftICE
szAnalysisTool_6  DB "\\.\SICE", 0h                  ; SoftICE
szAnalysisTool_7  DB "\\.\SIWVID", 0h                ; SoftICE
szAnalysisTool_8  DB "\\.\REGSYS", 0h                ; RegMon
szAnalysisTool_9  DB "\\.\REGVXG", 0h                ; RegMon
szAnalysisTool_A  DB "\\.\RING0", 0h                 ; OllyAdvanced
szAnalysisTool_B  DB "\\.\TRW", 0h                   ; TRW
szAnalysisTool_C  DB "\\.\SPCOMMAND", 0h             ; Syser
szAnalysisTool_D  DB "\\.\SYSER", 0h                 ; Syser
szAnalysisTool_E  DB "\\.\SYSERBOOT", 0h             ; Syser
szAnalysisTool_F  DB "\\.\SYSERDBGMSG", 0h           ; Syser


szAnalysisTool_10 DB "\\.\SYSERLANGUAGE", 0h         ; Syser
szEmptyString     DB 0h

szExplorerExe  DB "explorer.exe ", 0h
lpProcessEntry32  DD 128h ;sizeof(PROCESSENTRY32)
                            DB 124h dup (?)
lpCt32sCounters DB 0ffh, 1, ?, ?

ddRtlProcessFlsDataStructure        DD 0, offset @RtlProcessFlsDataSuccess, 0, 1
szRtlProcessFlsDataName             DB "RtlProcessFlsData", 0h
ddRtlProcessFlsDataOverwriteAddress DD 0h
ddRtlProcessFlsDataOverwriteValue   DD 0h

MBD_OLDProtect DD 02040001h

ddExcContext  DD 10002h 
dbExcContext2 DB 0B0h



; #### Structures and constants used in tests #############################

CRC DD 0CD0557Bh

CRC_Table DD 00000000h, 77073096h, 0EE0E612Ch, 990951BAh
DD 076DC419h, 706AF48Fh, 0E963A535h, 9E6495A3h
DD 0EDB8832h, 79DCB8A4h, 0E0D5E91Eh, 97D2D988h
DD 09B64C2Bh, 7EB17CBDh, 0E7882D07h, 90BF1D91h
DD 1DB71064h, 6AB020F2h, 0F3B97148h, 84BE41DEh
DD 1ADAD47Dh, 6DDDE4EBh, 0F4D4B551h, 83D385C7h
DD 136C9856h, 646BA8C0h, 0FD62F97Ah, 8A65C9ECh
DD 14015C4Fh, 63066CD9h, 0FA0F3D63h, 8D080DF5h
DD 3B6E20C8h, 4C69105Eh, 0D56041E4h, 0A2677172h
DD 3C03E4D1h, 4B04D447h, 0D20D85FDh, 0A50AB56Bh
DD 35B5A8FAh, 4282986Ch, 0DBBBC9D6h, 0AC8CF940h
DD 32D86CE3h, 45DF5C75h, 0DCD60DCFh, 0ABD13D59h
DD 26D930ACh, 51DE003Ah, 0C8D75180h, 0BFD06116h
DD 21B4F485h, 56B3C423h, 0CFBA9599h, 0B8BDA50Fh
DD 2802B89Eh, 5F058808h, 0C60CD9B2h, 0B10BE924h
DD 2F6F7C87h, 58684C11h, 0C1611DABh, 0B6662D3Dh
DD 76DC4190h, 01DB7106h, 98D220BCh, 0EFD5102Ah
DD 71B18589h, 06B6B51Fh, 9FBFE4A5h, 0E8B8D433h
DD 7807C9A2h, 0F00F934h, 9609A88Eh, 0E10E9818h
DD 7F6A0DBBh, 086D3D2Dh, 91646C97h, 0E6635C01h
DD 6B6B51F4h, 1C6C6162h, 856530D8h, 0F262004Eh
DD 6C0695EDh, 1B01A57Bh, 8208F4C1h, 0F50FC457h
DD 65B0D9C6h, 12B7E950h, 8BBEB8EAh, 0FCB9887Ch
DD 62DD1DDFh, 15DA2D49h, 8CD37CF3h, 0FBD44C65h
DD 4DB26158h, 3AB551CEh, 0A3BC0074h, 0D4BB30E2h
DD 4ADFA541h, 3DD895D7h, 0A4D1C46Dh, 0D3D6F4FBh
DD 4369E96Ah, 346ED9FCh, 0AD678846h, 0DA60B8D0h
DD 44042D73h, 33031DE5h, 0AA0A4C5Fh, 0DD0D7CC9h
DD 5005713Ch, 270241AAh, 0BE0B1010h, 0C90C2086h
DD 5768B525h, 206F85B3h, 0B966D409h, 0CE61E49Fh
DD 5EDEF90Eh, 29D9C998h, 0B0D09822h, 0C7D7A8B4h
DD 59B33D17h, 2EB40D81h, 0B7BD5C3Bh, 0C0BA6CADh
DD 0EDB88320h, 9ABFB3B6h, 03B6E20Ch, 74B1D29Ah
DD 0EAD54739h, 9DD277AFh, 04DB2615h, 73DC1683h
DD 0E3630B12h, 94643B84h, 0D6D6A3Eh, 7A6A5AA8h
DD 0E40ECF0Bh, 9309FF9Dh, 0A00AE27h, 7D079EB1h
DD 0F00F9344h, 8708A3D2h, 1E01F268h, 6906C2FEh
DD 0F762575Dh, 806567CBh, 196C3671h, 6E6B06E7h
DD 0FED41B76h, 89D32BE0h, 10DA7A5Ah, 67DD4ACCh
DD 0F9B9DF6Fh, 0BEBEEFF9h, 17B7BE43h, 60B08ED5h
DD 0D6D6A3E8h, 0A1D1937Eh, 38D8C2C4h, 4FDFF252h
DD 0D1BB67F1h, 0A6BC5767h, 3FB506DDh, 48B2364Bh
DD 0D80D2BDAh, 0AF0A1B4Ch, 36034AF6h, 41047A60h
DD 0DF60EFC3h, 0A867DF55h, 316E8EEFh, 4669BE79h
DD 0CB61B38Ch, 0BC66831Ah, 256FD2A0h, 5268E236h
DD 0CC0C7795h, 0BB0B4703h, 220216B9h, 5505262Fh
DD 0C5BA3B8Eh, 0B2BD0B28h, 2BB45A92h, 5CB36A04h
DD 0C2D7FFA7h, 0B5D0CF31h, 2CD99E8Bh, 5BDEAE1Dh
DD 9B64C2B0h, 0EC63F226h, 756AA39Ch, 026D930Ah
DD 9C0906A9h, 0EB0E363Fh, 72076785h, 05005713h
DD 95BF4A82h, 0E2B87A14h, 7BB12BAEh, 0CB61B38h
DD 92D28E9Bh, 0E5D5BE0Dh, 7CDCEFB7h, 0BDBDF21h
DD 86D3D2D4h, 0F1D4E242h, 68DDB3F8h, 1FDA836Eh
DD 81BE16CDh, 0F6B9265Bh, 6FB077E1h, 18B74777h
DD 88085AE6h, 0FF0F6A70h, 66063BCAh, 11010B5Ch
DD 8F659EFFh, 0F862AE69h, 616BFFD3h, 166CCF45h
DD 0A00AE278h, 0D70DD2EEh, 4E048354h, 3903B3C2h
DD 0A7672661h, 0D06016F7h, 4969474Dh, 3E6E77DBh
DD 0AED16A4Ah, 009D65ADCh, 40DF0B66h, 37D83BF0h
DD 0A9BCAE53h, 0DEBB9EC5h, 47B2CF7Fh, 30B5FFE9h
DD 0BDBDF21Ch, 0CABAC28Ah, 53B39330h, 24B4A3A6h
DD 0BAD03605h, 0CDD70693h, 54DE5729h, 23D967BFh
DD 0B3667A2Eh, 0C4614AB8h, 5D681B02h, 2A6F2B94h
DD 0B40BBE37h, 0C30C8EA1h, 5A05DF1Bh, 2D02EF8Dh

float_olly_crash DB 000h, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 03dh, 040h, 042h, 06fh, 052h

fpuenv  STRUCT
ControlWord           DD 0
StatusWord            DD 0
TagWord               DD 0
InstructionPointer    DD 0
CodeSegment           DD 0
OperandAddress        DD 0
DataSegment           DD 0
fpuenv  ENDS

fpuenv_store   fpuenv  {}

; The following code allows introduction of a TLS data structure and callback
; chain in MASM32. It is based on elicz's tlsinasm tutorial, once but no longer
;  available at www.anticracking.sk/EliCZ/
; - a local copy was used instead.

TLS_DIRECTORY    STRUCT
 lpTlsDataStart LPDWORD ?
 lpTlsDataEnd   LPDWORD ?
 lpTlsIndex     LPDWORD ?
 lpTlsCallbacks LPDWORD ?
 dwZeroFillSize   DWORD ?
 dwCharacteristic DWORD ?
TLS_DIRECTORY      ENDS

; this name is required and must be declared PUBLIC

PUBLIC _tls_used
_tls_used TLS_DIRECTORY <tlsStart, tlsEnd, tlsIndex, tlsCallbacks, 0, ?>

tlsCallbacks DWORD TLS_Prologue, TLS_NtQueryInformation, TLS_performSetup
tlsDelimiter DWORD 0



; #########################################################################
; #########################################################################

.DATA?

tlsIndex DWORD  ?

argc             DB 100h DUP(?)
szCmdLineBuffer  DB 100h DUP(?)
szOutputFilePath DB 100h DUP(?)
szFormatBuffer   DB 100h DUP(?)

lpCurrentTitle DD ?
lpCurrentRef   DD ?
lpCurrentText  DD ?
dwPrintTestTitle DD ?

; used for poor man's exception handling, simply restoring the stack
; layout and ignoring the generated records
dwSavedStackPointer DD ?
dwSavedSubStackPointer DD ?

dwOldSeh DD ?

startBuffer DB 100 DUP(?)
exitBuffer  DB 100 DUP(?)

sldtTable DW 64 DUP(?)
sidtTable DW 64 DUP(?)
sgdtTable DW 64 DUP(?)

lpFakeTable DW 50h DUP(?)

Ring3_HeapEntry DB 01Ch DUP(?)

dwAllocatedAddress DD ?

CreateFileLabel DB 104h DUP (?)
szWINDIR        DB 512 DUP(?)

lpcbOllyData DD ?
lpcbSICEData DD ?
hOllyRegKey  DD ?
hSICERegKey  DD ?

szOllyRegValueBuffer DB 256h DUP(?)
szSICERegValueBuffer DB 256h DUP(?)

dwCheckRemoteDebuggerPresentResult DD ?


; #########################################################################
; #### Main code ##########################################################
; Structure:
; - Macros
; - Menu
; - functions for convenient use
; - Implementations of Tests
; - Implementation of TLS callback fuctions
; #########################################################################

.CODE

; #### Macros #############################################################

M_insert_4_NOPs MACRO
    NOP
    NOP
    NOP
    NOP
ENDM

M_insert_16_NOPs MACRO
     M_insert_4_NOPs
     M_insert_4_NOPs
     M_insert_4_NOPs
     M_insert_4_NOPs
ENDM



start:

; #### Menu ###############################################################
; #### Test are grouped in the following way ##############################

; Timing Tests
; Flags
; Anti-Stepping
; API Calls
; Debugger specific (olly, softice, ...)
; Exception based
; Integrity (CRC)
; (Error Codes? -> LastError)
; OS-dependant (Vista)
; NtQueryInformationProcess based
; Miscellaneous
; Virtual Machine Detection
; GetIP methods


; #### Welcome message ####################################################

PUSH OFFSET szWelcomeTitle
CALL antiRE_print
PUSH OFFSET szDisclaimerText
CALL antiRE_print

PUSH OFFSET szStartText
CALL antiRE_waitForAnyKey

M_insert_4_NOPs



M_insert_4_NOPs

; #### Exception-based ####################################################

PUSH OFFSET szGroupDivider
PUSH OFFSET groupTitleIntro
PUSH OFFSET szGroupExceptions
CALL printGroupTitle
NOP
NOP


; SEH Tests
MOV eax, OFFSET szSehTitle
CALL @IntroSeh


M_insert_4_NOPs


; #### Show results and exit ##############################################

MOV [dwPrintTestTitle], 1
PUSH OFFSET szGroupDivider
PUSH OFFSET szEmptyString
PUSH OFFSET szResults
CALL printGroupTitle
NOP
NOP

; End
CALL @Finish
PUSH OFFSET szExitText
CALL antiRE_waitForAnyKey
PUSH -1
CALL ExitProcess

M_insert_16_NOPs
M_insert_16_NOPs



; #### convenience functions ##############################################



parseCommandLineArguments proc
    invoke GetCommandLineW
    invoke CommandLineToArgvW, eax, offset [argc]
    MOV ecx, dword ptr [argc]
    MOV edx, eax
    @getArgvLoop:
        PUSH ecx
        MOV ebx, eax ; get next array element
        ADD eax, 4h
        PUSH eax
        invoke WideCharToMultiByte, CP_ACP, 0, [ebx], -1, offset szCmdLineBuffer, sizeof szCmdLineBuffer, 0, 0
        invoke lstrcmp, offset szCmdLineBuffer, offset szArgumentA
        TEST eax, eax
        JNE @skipArgumentA
	        MOV[dwWaitForAnyKey], 1h
        @skipArgumentA:
        invoke lstrcmp, offset szCmdLineBuffer, offset szArgumentO
        TEST eax, eax
        JNE @skipArgumentO
           MOV [dwPrintToFile], 1h
        @skipArgumentO:
        POP eax
        POP ecx
    loop @getArgvLoop
    MOV eax, [dwPrintToFile]
    TEST eax, eax
    JE @getArgvExit
        CALL createOutputFile
    @getArgvExit:

    RET
parseCommandLineArguments endp

M_insert_4_NOPs



createOutputFile proc
    PUSH OFFSET szOutputFilePath
    PUSH 255
    CALL GetCurrentDirectory
    PUSH OFFSET szBackSlash
    PUSH OFFSET szOutputFilePath
    CALL szCatStr
    PUSH OFFSET szOutputFilename
    PUSH OFFSET szOutputFilePath
    CALL szCatStr
    PUSH 0
    PUSH 80h
    PUSH 2
    PUSH 0
    PUSH 3
    PUSH 40000000h
    PUSH OFFSET szOutputFilePath ; create always new file
    CALL CreateFileA
    MOV [hReportOutputFile], eax

    RET
createOutputFile endp

M_insert_4_NOPs



SetMemoryWritable proc
    PUSH ebp
    MOV ebp, esp
    PUSH ebx
    PUSH edx
    PUSH 0
    CALL GetModuleHandle
    MOV edx, eax ; EDX will hold base addr
    SUB esp, 4
    MOV ebx, esp
    PUSH ebx
    PUSH 040h ; READ_WRITE_EXECUTE
    MOV ebx, dword ptr ds:[edx + 03Ch] ; offset to PE header
    ADD ebx, edx
    MOV eax, dword ptr ds:[ebx + 01Ch] ; size of code
    ADD eax, 01000h ; size of PE header
    PUSH eax
    PUSH edx ; start addr (= base addr)
    CALL VirtualProtect
    POP eax ; throw away oldProtect
    POP edx
    POP ebx
    POP ebp

    RET
SetMemoryWritable endp

M_insert_4_NOPs



; test status messages

printTestSuccessful proc
    ADD [dwSuccessCounter], 1
    MOV eax, dwPrintOnlyFailedTests
    TEST eax, eax
    JNZ @skipPrintTestSuccessful
        PUSH OFFSET szTestSuccessfulMessage
        CALL antiRE_print
    @skipPrintTestSuccessful:
    
    RET 
printTestSuccessful endp

M_insert_4_NOPs




printTestFailed proc
    ADD [dwFailCounter], 1
    MOV eax, dwPrintOnlyFailedTests
    TEST eax, eax
    JE @skipPrintDelayedFailedTestName
        MOV [dwPrintTestTitle], 1
        MOV eax, lpCurrentTitle
        PUSH eax
        MOV eax, lpCurrentRef
        PUSH eax
        MOV eax, lpCurrentText
        PUSH eax
        CALL storeAndPrintTestTitle
    @skipPrintDelayedFailedTestName:
    PUSH OFFSET szTestFailedMessage
    CALL antiRE_print
        
    RET 
printTestFailed endp

M_insert_4_NOPs



printTestAborted proc
    MOV eax, dwPrintOnlyFailedTests
    TEST eax, eax
    JZ @skipPrintDelayedAbortTestName
        MOV [dwPrintTestTitle], 1
        MOV eax, lpCurrentTitle
        PUSH eax
        MOV eax, lpCurrentRef
        PUSH eax
        MOV eax, lpCurrentText
        PUSH eax
        CALL storeAndPrintTestTitle
    @skipPrintDelayedAbortTestName:
    PUSH OFFSET szTestAbortedMessage
    CALL antiRE_print
        
    RET 
printTestAborted endp

M_insert_4_NOPs



; subtest status messages

printSubtestSuccessful proc
    MOV eax, dwPrintOnlyFailedTests
    TEST eax, eax
    JNZ @skipPrintSubtestSuccessful
        PUSH OFFSET szSubtestSuccessfulMessage
        CALL antiRE_print
    @skipPrintSubtestSuccessful:
        
    RET 
printSubtestSuccessful endp

M_insert_4_NOPs



printSubtestFailed proc
    ADD [dwSehTestFailCounter], 1
    MOV eax, dwPrintOnlyFailedTests
    TEST eax, eax
    JZ @skipPrintSubtestFailed
        PUSH OFFSET szSubtestFailedMessage
        CALL antiRE_print
    @skipPrintSubtestFailed:
        
    RET 
printSubtestFailed endp

M_insert_4_NOPs



antiRE_print proc string:DWORD
    invoke crt_printf, string
    mov eax, [hReportOutputFile]
    test eax, eax
    JNE @write_to_file
        JMP @antiRE_print_exit
    @write_to_file:
    ASSUME fs:nothing
    PUSH OFFSET @antiRE_print_sehExit
    PUSH DWORD PTR fs:[0]
    MOV fs:[0],esp
    MOV [dwSavedSubStackPointer], esp
    ; fast strlen
    MOV edi, string
    XOR ecx, ecx
    XOR eax, eax
    NOT ecx
    CLD
    REPNE SCASB
    NOT ecx
    DEC ecx
    ; write contents to file
    PUSH 0
    PUSH OFFSET dwTemporary
    PUSH ecx
    PUSH string
    PUSH [hReportOutputFile]
    CALL WriteFile
    JMP @antiRE_print_exit
        @antiRE_print_sehExit:
        MOV esp, [dwSavedSubStackPointer]
        POP DWORD PTR fs:[0]
        ADD esp,4
    @antiRE_print_exit:

    RET
antiRE_print endp

M_insert_4_NOPs



printDwordFormatted proc szMessage:DWORD, dwPointer:DWORD, format:DWORD
    MOV eax, dwPrintTestTitle
    TEST eax, eax
    JNZ @PrintDwordFormatted
        MOV eax, dwPrintOnlyFailedTests
        TEST eax, eax
        JNZ @skipPrintDwordFormatted
            @PrintDwordFormatted:
            PUSH szMessage
            CALL antiRE_print
            invoke wsprintf, OFFSET szFormatBuffer, format, dwPointer
            PUSH OFFSET szFormatBuffer
            CALL antiRE_print
    @skipPrintDwordFormatted:
    RET
printDwordFormatted endp

M_insert_4_NOPs



storeAndPrintTestTitle proc lpTestText:DWORD, lpTestRef:DWORD, lpTestTitle:DWORD
    MOV eax, lpTestTitle
    MOV dword ptr ds:[lpCurrentTitle], eax
    MOV eax, lpTestRef
    MOV dword ptr ds:[lpCurrentRef], eax
    MOV eax, lpTestText
    MOV dword ptr ds:[lpCurrentText], eax
    MOV eax, dwPrintTestTitle
    TEST eax, eax
    JNZ @PrintTestTitle
        ADD [dwTestCounter], 1
        MOV eax, dwPrintOnlyFailedTests
        TEST eax, eax
        JNZ @skipPrintTestTitle
            @PrintTestTitle:
            PUSH OFFSET szTestDivider
            CALL antiRE_print
            PUSH OFFSET szReportFormatInt
            PUSH dwTestCounter
            PUSH OFFSET szTestText
            CALL printDwordFormatted
            PUSH lpTestTitle
            CALL antiRE_print
            PUSH lpTestRef
            CALL antiRE_print
            PUSH lpTestText
            CALL antiRE_print
            MOV [dwPrintTestTitle], 0
    @skipPrintTestTitle:
    RET
storeAndPrintTestTitle ENDP

M_insert_4_NOPs



printGroupTitle proc groupTitle:DWORD, groupHeading:DWORD, dummy:DWORD
    MOV eax, dwPrintTestTitle
    TEST eax, eax
    JNZ @PrintGroupTitle
        MOV eax, dwPrintOnlyFailedTests
        TEST eax, eax
        JNZ @skipPrintGroupTitle
            @PrintGroupTitle:
            PUSH OFFSET szNewLine
            CALL antiRE_print
            PUSH OFFSET szGroupDivider
            CALL antiRE_print
            PUSH groupHeading
            CALL antiRE_print
            PUSH groupTitle
            CALL antiRE_print
            PUSH OFFSET szGroupDivider
            CALL antiRE_print
            PUSH OFFSET szContinueText
            CALL antiRE_waitForAnyKey
            MOV [dwPrintTestTitle], 0
            NOP
            NOP
    @skipPrintGroupTitle:
    RET
printGroupTitle  ENDP

M_insert_4_NOPs



antiRE_waitForAnyKey proc string:DWORD
    XOR eax, eax
    MOV eax, [dwWaitForAnyKey]
    TEST eax, eax
    JE @dontWaitForAnyKey
        PUSH string
        CALL antiRE_print
        invoke crt__getch
    @dontWaitForAnyKey:

    RET
antiRE_waitForAnyKey endp



M_insert_16_NOPs
M_insert_16_NOPs



; #########################################################################
; #### Start of test and demo implementations #############################


; #########################################################################
; Timing Test: RDTSC

@IntroTimingRdtsc:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szTimingRdtscTitle
PUSH OFFSET szTimingRdtscRef
PUSH OFFSET szTimingRdtscText
CALL storeAndPrintTestTitle

NOP
NOP

@TestTimingRdtsc:
RDTSC
XCHG esi, eax
MOV edi, edx
RDTSC
SUB eax, esi
SBB edx, edi
JNE @TestTimingRdtscFailed
    CMP eax, 500h
JNBE @TestTimingRdtscFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestTimingRdtscFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Timing Test: GetTickCount()

@IntroTimingGtc:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szTimingGtcTitle
PUSH OFFSET szTimingGtcRef
PUSH OFFSET szTimingGtcText
CALL storeAndPrintTestTitle

NOP
NOP

@TestTimingGtc:
CALL GetTickCount
XCHG ebx, eax
CALL GetTickCount
SUB eax, ebx
CMP eax, 10h
JNBE @TestTimingGtcFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestTimingGtcFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Timing Test: QueryPermanceCounter()

@IntroTimingQpc:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szTimingQpcTitle
PUSH OFFSET szTimingQpcRef
PUSH OFFSET szTimingQpcText
CALL storeAndPrintTestTitle

NOP
NOP

@TestTimingQpc:
SUB esp,010h
LEA eax, [esp]
PUSH eax
CALL QueryPerformanceCounter
LEA eax, [esp + 8]
PUSH eax
CALL QueryPerformanceCounter
POP eax
POP ebx
POP ecx
POP edx
SUB ecx, eax
SBB edx, ebx
JNE @TestTimingQpcFailed
    CMP ecx, 10h
JNBE @TestTimingQpcFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestTimingQpcFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs



; #########################################################################
; Timing Test: Combined timers for emulation detection

@IntroTimingEmulation:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szTimingEmulationTitle
PUSH OFFSET szTimingEmulationRef
PUSH OFFSET szTimingEmulationText
CALL storeAndPrintTestTitle

NOP
NOP

@TestTimingEmulation:
PUSH ebx
CALL GetTickCount
MOV ebx, eax
PUSH 500 
CALL Sleep
CALL GetTickCount
SUB eax, ebx
CMP eax, 500
JL @TestTimingEmulationFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestTimingEmulationFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs


; #########################################################################
; Timing Trap based on CPU perfomance counter (RDPMC)
; works only if corresponding flag in CR4 is set

@IntroTimingRdpmc:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szTimingRdpmcTitle
PUSH OFFSET szTimingRdpmcRef
PUSH OFFSET szTimingRdpmcText
CALL storeAndPrintTestTitle

NOP
NOP

@TestTimingRdpmc:
PUSH OFFSET @TestTimingRdpmcAborted
ASSUME fs:nothing
PUSH DWORD PTR fs:[0h]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
XOR ecx, ecx ;read 32-bit counter 0
RDPMC    ; if flag is enabled, this will throw an exception and abort the test
    XCHG ebx, eax
    RDPMC
    SUB eax, ebx
    CMP eax, 500h
    JNBE @TestTimingRdpmcFailed
        MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful


        MOV esp, [dwSavedStackPointer]
        POP DWORD PTR fs:[0]
        ADD esp,4
        POP ebp

        RET
    @TestTimingRdpmcFailed:
    MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]

    ADD esp,4
    POP ebp

    RET
@TestTimingRdpmcAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; PEB Heap Flags as Debug Indicator


@IntroPEBGlobalFlags:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szPEBGlobalFlagsTitle
PUSH OFFSET szPEBGlobalFlagsRef
PUSH OFFSET szPEBGlobalFlagsText
CALL storeAndPrintTestTitle

NOP
NOP

@TestPEBGlobalFlags:
CALL GetVersion
CMP al, 06h
JNBE @PEBGlobalFlagsAborted
MOV ax, gs
TEST ax, ax
JNZ @PEBGlobalFlags64bit
ASSUME fs:nothing
MOV ebx, dword ptr fs:[30h]
MOV al, byte ptr [ebx+68h]
JMP @PEBGlobalFlagsEvaluate
@PEBGlobalFlags64bit:
ASSUME fs:nothing
MOV ebx, dword ptr fs:[30h]
MOV al, byte ptr [ebx+010bch]
@PEBGlobalFlagsEvaluate:
AND al, 70h
CMP al, 70h    ; Check if PEB.NtGlobalFlag != 0
JE @TestPEBGlobalFlagsFailed
    NOP
    NOP
    MOV eax,[ebx+18h]  ;eax = PEB.ProcessHeap
    CMP DWORD PTR [eax+0Ch], 2h    ; Check PEB.ProcessHeap.Flags
    JNE @TestPEBGlobalFlagsFailed
	NOP
	NOP
	CMP DWORD PTR [eax+10h], 0h   ; Check PEB.ProcessHeap.ForceFlags
	JNE @TestPEBGlobalFlagsFailed
	    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestPEBGlobalFlagsFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET
    
@PEBGlobalFlagsAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; IsDebuggerPresent() API Call


@IntroIsDebuggerPresent:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szIsDebuggerPresentTitle
PUSH OFFSET szIsDebuggerPresentRef
PUSH OFFSET szIsDebuggerPresentText
CALL storeAndPrintTestTitle

NOP
NOP

@TestIsDebuggerPresent:
CALL IsDebuggerPresent
CMP eax,01h
JE @TestIsDebuggerPresentFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestIsDebuggerPresentFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; IsDebuggerPresent() inline implementation (directly read from PEB)


@IntroIsDebuggerPresent2:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szIsDebuggerPresent2Title
PUSH OFFSET szIsDebuggerPresent2Ref
PUSH OFFSET szIsDebuggerPresent2Text
CALL storeAndPrintTestTitle

NOP
NOP

@TestIsDebuggerPresent2:
ASSUME fs:nothing
MOV eax, DWORD PTR fs:[18h]
MOV eax, DWORD PTR ds:[eax+30h]
MOVZX eax, BYTE PTR ds:[eax+2h]
CMP eax,1
JE @TestIsDebuggerPresent2Failed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestIsDebuggerPresent2Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; FindWindow() used to identify well-known window names of debuggers


@IntroFindWindow:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szFindWindowTitle
PUSH OFFSET szFindWindowRef
PUSH OFFSET szFindWindowText
CALL storeAndPrintTestTitle

NOP
NOP

@TestFindWindow:
PUSH 0
PUSH OFFSET szOllyDbgFindWindow
CALL FindWindow
TEST eax, eax
JNE @TestFindWindowFailed
    PUSH 0
    PUSH OFFSET szOllyDbgFindShadowWindow
    CALL FindWindow
    TEST eax, eax
	JNE @TestFindWindowFailed
	MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
	POP ebp

	RET
@TestFindWindowFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; CheckRemoteDebuggerPresent() API Call


@IntroRemoteDebugger:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRemoteDebuggerTitle
PUSH OFFSET szRemoteDebuggerRef
PUSH OFFSET szRemoteDebuggerText
CALL storeAndPrintTestTitle

NOP
NOP

@TestRemoteDebugger:
PUSH OFFSET dwCheckRemoteDebuggerPresentResult
PUSH -1
CALL CheckRemoteDebuggerPresent
MOV eax, DWORD PTR[dwCheckRemoteDebuggerPresentResult]
TEST eax, eax
JNE @TestRemoteDebuggerFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestRemoteDebuggerFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; NtQueryInformationProcess(): ProcessDebugPort != 0?


@IntroNTQueryInformation:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szNtQueryInformationTitle
PUSH OFFSET szNtQueryInformationRef
PUSH OFFSET szNtQueryInformationText
CALL storeAndPrintTestTitle

NOP
NOP

@TestNTQueryInformation:
MOV eax, -1
PUSH eax
MOV ebx,esp
PUSH 0
PUSH 4
PUSH ebx
PUSH 7
PUSH eax
CALL NtQueryInformationProcess
POP eax
TEST eax, eax
JNE @TestNTQueryInformationFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestNTQueryInformationFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; NtQuerySystemInformation():
; called with Information class SystemKernelDebuggerInformation
; returns: KdDebuggerNotPresent (AH) KdDebuggerEnabled (AL)


@IntroNtQuerySystemInformation:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szNtQuerySystemInformationTitle
PUSH OFFSET szNtQuerySystemInformationRef
PUSH OFFSET szNtQuerySystemInformationText
CALL storeAndPrintTestTitle

NOP
NOP


@TestNtQuerySystemInformation:
PUSH eax
MOV eax, esp
PUSH 0
PUSH 2 ;SystemInformationLength
PUSH eax
PUSH 23h ;SystemKernelDebuggerInformation
CALL NtQuerySystemInformation
POP eax
TEST ah, ah
JE @TestNtQuerySystemInformationFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestNtQuerySystemInformationFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; OllyInvisible Detection through calling CsrGetProcessId


@IntroOllyInvisible:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szOllyInvisibleTitle
PUSH OFFSET szOllyInvisibleRef
PUSH OFFSET szOllyInvisibleText
CALL storeAndPrintTestTitle

NOP
NOP

@TestOllyInvisible:
CALL CsrGetProcessId
TEST eax, eax
JE @TestOllyInvisibleFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestOllyInvisibleFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Single Step Detection (pushing trap flag)


@IntroSingleStepDetection:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szSingleStepDetectionTitle
PUSH OFFSET szSingleStepDetectionRef
PUSH OFFSET szSingleStepDetectionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSingleStepDetection:
ASSUME fs:nothing
PUSH OFFSET @TestSingleStepDetectionSehExit
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH 0100h
POPFD
NOP
NOP
JMP @TestSingleStepDetectionFailed

    @TestSingleStepDetectionSehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestSingleStepDetectionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; MOV SS: can cause an instruction to be skipped which leads to detection

@IntroMovSS:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szMovSSTitle
PUSH OFFSET szMovSSRef
PUSH OFFSET szMovSSText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH ss
POP ss
PUSHFD
POP EAX
TEST ah, 1
JNE @TestMovSSFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestMovSSFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; check if INT 41h is adjusted to DPL 3 / can be called from ring 3

@IntroInt41:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInt41Title
PUSH OFFSET szInt41Ref
PUSH OFFSET szInt41Text
CALL storeAndPrintTestTitle

NOP
NOP

PUSH OFFSET @TestInt41SehExit
ASSUME fs:nothing
PUSH DWORD PTR fs:[0h]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
XOR eax, eax
MOV al, 4fh
INT 41h
JMP @TestInt41Failed
    @TestInt41SehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestInt41Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; OllyDbg - HideDebuggerPlugin: detect OpenProcess() hook insertion

@IntroOpenProcess:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szOpenProcessTitle
PUSH OFFSET szOpenProcessRef
PUSH OFFSET szOpenProcessText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH OFFSET szKernel32Dll
CALL GetModuleHandle
PUSH OFFSET szOpenProcess ;OpenProcess
PUSH eax
CALL GetProcAddress
CMP BYTE PTR[eax+6],0EAh
JE @TestOpenProcessFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestOpenProcessFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; OllyDbg - Registry: detect if a debugger (except drwtsn32) is registered

@IntroRegistryKey:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRegistryKeyTitle
PUSH OFFSET szRegistryKeyRef
PUSH OFFSET szRegistryKeyText
CALL storeAndPrintTestTitle

NOP
NOP

@TestRegistryKey:
MOV lpcbOllyData,256h
INVOKE RegOpenKeyEx, HKEY_LOCAL_MACHINE, ADDR szOllyKey, 0,KEY_WRITE OR KEY_READ, ADDR hOllyRegKey
INVOKE RegQueryValueEx, hOllyRegKey, ADDR szIsOllyKey, 0, ADDR szREGSZ, ADDR szOllyRegValueBuffer, ADDR lpcbOllyData
OR eax, eax
JNE @TestRegistryKeyExit
	PUSH edx
	PUSH ecx
	MOV edx, OFFSET szOllyRegValueBuffer+1
	MOV ecx, lpcbOllyData
	@TestRegistryKeySeekQuote:
	    CMP BYTE PTR[edx],'"'
	    JE @TestRegistryKeyFailed
		    INC edx
		    LOOP @TestRegistryKeySeekQuote
          POP ecx
          POP edx
          JMP @TestRegistryKeyExit
      @TestRegistryKeyFailed:
      POP ecx
      POP edx
      MOV eax, OFFSET szTestFailedMessage
      CALL printTestFailed
      POP ebp

      RET
@TestRegistryKeyExit:
MOV eax, OFFSET szTestSuccessfulMessage
CALL printTestSuccessful
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Kill OllyDbg 1.10 with certain floating point values

@IntroFLDKillOllyDbg:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szFLDKillOllyDbgTitle
PUSH OFFSET szFLDKillOllyDbgRef
PUSH OFFSET szFLDKillOllyDbgText
CALL storeAndPrintTestTitle

NOP
NOP

lea eax, [float_olly_crash]
mov byte ptr ds:[eax], 0FFh
fld tbyte ptr ds:[float_olly_crash]
MOV eax, OFFSET szTestSuccessfulMessage
CALL printTestSuccessful
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; trigger CMPXCHG8B lock prefix (CPU bug): SoftIce trap

@IntroCMPXCHG8B:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szCMPXCHG8BTitle
PUSH OFFSET szCMPXCHG8BRef
PUSH OFFSET szCMPXCHG8BText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCMPXCHG8B:
ASSUME fs:nothing
PUSH OFFSET @TestCMPXCHG8BError
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer],esp
NOP
NOP
DB 0F0h, 0Fh, 0C7h, 0C8h
NOP
NOP
JMP @TestCMPXCHG8BFailed
	@TestCMPXCHG8BError:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestCMPXCHG8BFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Detection of various analysis tool drivers

@IntroAnalysisDriver:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szAnalysisDriverTitle
PUSH OFFSET szAnalysisDriverRef
PUSH OFFSET szAnalysisDriverText
CALL storeAndPrintTestTitle

NOP
NOP

@TestAnalysisDriver:
XOR eax, eax
MOV edi, OFFSET szAnalysisTool_0
@NextAnalysisDriver:
PUSH 0h                         ; hTemplateFile
PUSH FILE_ATTRIBUTE_NORMAL      ; Hidden/Normal
PUSH OPEN_EXISTING              ; OPEN_EXISTING
PUSH 0h                         ; pSecurity
PUSH FILE_SHARE_READ            ; ShareMode = File Share Write
PUSH FILE_FLAG_WRITE_THROUGH    ; Access
PUSH edi                        ; Path
CALL CreateFileA
INC eax
JNE @TestAnalysisDriverFailed
	OR ecx, -1
	REPNE scasb
	CMP byte ptr ds:[edi], al
	JNE @NextAnalysisDriver
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		POP ebp

		RET
@TestAnalysisDriverFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; SoftIce Detection through Registry

@IntroSoftIceRegistry:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szSoftIceRegistryTitle
PUSH OFFSET szSoftIceRegistryRef
PUSH OFFSET szSoftIceRegistryText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSoftIceRegistry:
MOV lpcbSICEData, 256h
INVOKE RegOpenKeyEx, HKEY_LOCAL_MACHINE, ADDR szSICEKey, 0,KEY_WRITE or KEY_READ, ADDR hSICERegKey
PUSH OFFSET lpcbSICEData
PUSH OFFSET szSICERegValueBuffer
PUSH OFFSET szREGSZ
PUSH 0
PUSH OFFSET szIsSICEKey
PUSH hSICERegKey
CALL RegQueryValueEx
TEST eax, eax
JE @TestSoftIceRegistryFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestSoftIceRegistryFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; SoftIce Detection through szWinICE.dat

@IntroSoftIceWinICE:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szSoftIceWinICETitle
PUSH OFFSET szSoftIceWinICERef
PUSH OFFSET szSoftIceWinICEText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSoftIceWinICE:
PUSH 512
PUSH OFFSET szWINDIR
CALL GetWindowsDirectory
PUSH OFFSET szWinICE
PUSH OFFSET szWINDIR
CALL lstrcat
PUSH 0h
PUSH FILE_ATTRIBUTE_NORMAL
PUSH OPEN_EXISTING             ; OPEN_EXISTING
PUSH 0h
PUSH FILE_SHARE_READ           ; ShareMode = File Share Write
PUSH FILE_FLAG_WRITE_THROUGH
PUSH OFFSET szWINDIR
CALL CreateFileA
CMP eax, -1
JNE @TestSoftIceWinICEFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestSoftIceWinICEFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Ring3 Debugger Detection by examining heap memory for debug patterns

@IntroRing3Debugger:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRing3DebuggerTitle
PUSH OFFSET szRing3DebuggerRef
PUSH OFFSET szRing3DebuggerText
CALL storeAndPrintTestTitle

NOP
NOP

@TestRing3Debugger:
ASSUME fs:nothing
PUSH OFFSET @TestRing3DebuggerSehExit
PUSH DWORD PTR fs:[0]
MOV fs:[0], esp
MOV [dwSavedStackPointer], esp
MOV ebx, offset Ring3_HeapEntry
@TestRing3DebuggerLoop:
PUSH ebx
MOV eax, dword ptr fs:[30h]
PUSH dword ptr [eax + 18h]
CALL HeapWalk
CMP word ptr [ebx + 0ah], 4
JNE @TestRing3DebuggerLoop
	MOV edi, dword ptr [ebx]
	ADD edi, dword ptr [ebx + 4]
	MOV al, 0ABh
	MOV ecx, 8
	REPE scasb
	JE @TestRing3DebuggerFailed
		@TestRing3DebuggerSehExit:
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		MOV esp, [dwSavedStackPointer]
		POP DWORD PTR fs:[0]
		ADD esp, 4
		POP ebp

		RET
@TestRing3DebuggerFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; INT3 Exception triggered to confuse the debugger

@IntroInt3Exception:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szInt3ExceptionTitle
PUSH OFFSET szInt3ExceptionRef
PUSH OFFSET szInt3ExceptionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestInt3Exception:
ASSUME fs:nothing
PUSH OFFSET @TestInt3ExceptionSehExit
PUSH fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
INT 3h ; Exception
; old OllyDbg is not able to pass this exception correctly to the program and will loop here
JMP @TestInt3ExceptionFailed
	@TestInt3ExceptionSehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp, 4
    POP ebp

    RET
@TestInt3ExceptionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; OllyDbg (1.10) can be detected because of false instruction handling
; REP Int 1

@IntroInstructionPrefixDetection:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInstructionPrefixDetectionTitle
PUSH OFFSET szInstructionPrefixDetectionRef
PUSH OFFSET szInstructionPrefixDetectionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestInstructionPrefixDetection:
ASSUME fs:nothing
PUSH OFFSET @TestInstructionPrefixDetectionExit
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
DB 0F3h, 64h    ; Prefix
DB 0F1h, 90h    ; 1 byte INT 1h and a NOP for alignment
JMP @TestInstructionPrefixDetectionFailed
@TestInstructionPrefixDetectionExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp, 4
    POP ebp

	RET
@TestInstructionPrefixDetectionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Detection of a debugger through execution of code on crafted guard page

@IntroMemoryBreakpointDetection:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szMemoryBreakpointDetectionTitle
PUSH OFFSET szMemoryBreakpointDetectionRef
PUSH OFFSET szMemoryBreakpointDetectionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestMemoryBreakpointDetection:
ASSUME fs:nothing
PUSH OFFSET @TestMemoryBreakpointDetectionSehExit
PUSH fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH PAGE_READWRITE
PUSH MEM_COMMIT
PUSH 10000h
PUSH 0
CALL VirtualAlloc
MOV BYTE PTR[eax],0C3h    ; Write RET there
MOV DWORD PTR[dwAllocatedAddress], eax
PUSH OFFSET MBD_OLDProtect    ; Place Memory break-point
PUSH PAGE_EXECUTE_READ OR PAGE_GUARD
PUSH 00000010h
PUSH eax
CALL VirtualProtect
CALL [dwAllocatedAddress]
JMP @TestMemoryBreakpointDetectionFailed
	@TestMemoryBreakpointDetectionSehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp, 4
    POP ebp

    RET
@TestMemoryBreakpointDetectionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Scanning for Hardware Breakpoints

@IntroHardwareBreakpointDetection:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szHardwareBreakpointDetectionTitle
PUSH OFFSET szHardwareBreakpointDetectionRef
PUSH OFFSET szHardwareBreakpointDetectionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestHardwareBreakpointDetection:
ASSUME fs:nothing
PUSH OFFSET @TestHardwareBreakpointDetectionSehTrigger
PUSH fs:[0]
MOV  fs:[0], esp
MOV [dwSavedStackPointer], esp
XOR eax, eax
MOV DWORD PTR ds:[eax], eax    ; DIV zero, fire SEH
JMP @TestHardwareBreakpointDetectionFailed
	@TestHardwareBreakpointDetectionSehTrigger:
	PUSH EBP
	MOV EBP,esp
	MOV eax, DWORD PTR SS:[EBP+10h]
	; Check DRx registers
	CMP DWORD PTR ds:[eax + 4h], 0
	JNE @TestHardwareBreakpointDetectionFailed
	    CMP DWORD PTR ds:[eax + 8h], 0
	JNE @TestHardwareBreakpointDetectionFailed
	    CMP DWORD PTR ds:[eax + 0Ch], 0
	JNE @TestHardwareBreakpointDetectionFailed
	    CMP DWORD PTR ds:[eax + 10h], 0
	JNE @TestHardwareBreakpointDetectionFailed
		@TestHardwareBreakpointDetectionExit:
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		MOV esp, [dwSavedStackPointer]
		POP DWORD PTR fs:[0]
		ADD esp, 4
		POP ebp

		RET
@TestHardwareBreakpointDetectionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Detecting SoftICE by searching for an INT 3 at API function
;  SetUnhandledExceptionFilter

@IntroSoftICE3h:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szSoftICE3hTitle
PUSH OFFSET szSoftICE3hRef
PUSH OFFSET szSoftICE3hText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSoftICE3h:
MOV [dwSavedStackPointer], esp
PUSH OFFSET @TestSoftICE3hError
CALL SetUnhandledExceptionFilter
MOV [dwOldSeh], eax
MOV eax, OFFSET UnhandledExceptionFilter
MOV eax, [eax + 2]
MOV eax, [eax]
PUSH eax
PUSH DWORD PTR [dwOldSeh]
CALL SetUnhandledExceptionFilter
POP eax
CMP BYTE PTR [eax], 0cch
JZ @TestSoftICE3hFailed
	JMP @TestSoftICE3hExit
		@TestSoftICE3hError:
		MOV esp, [dwSavedStackPointer]
	@TestSoftICE3hExit:
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		POP ebp

		RET
@TestSoftICE3hFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Detection of Breakpoints by checksumming code with CRC32

@IntroCRCBreakpoint:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szCRCBreakpointTitle
PUSH OFFSET szCRCBreakpointRef
PUSH OFFSET szCRCBreakpointText
CALL storeAndPrintTestTitle

NOP
NOP
@TestCRC_StartMarker:
JMP @TestCRCBreakpoint
	TestCRCBreakpointSubroutine PROC
		MOV eax, 0FFFFFFFFh
		MOV edx, eax
		@TestCRCBreakpointSubroutineLoop:
		    PUSH ecx
		    XOR ebx, ebx
		    MOV bl, BYTE PTR [edi]
		    INC edi
		    XOR bl, al
		    SHL bx, 1
		    SHL bx, 1
		    ADD ebx, esi
		    MOV cx, WORD PTR [ebx + 2]
		    MOV bx, WORD PTR [ebx]
		    MOV al, ah
		    MOV ah, dl
		    MOV dl, dh
		    XOR dh, dh
		    XOR ax, bx
		    XOR dx, cx
		    POP ecx
		LOOP @TestCRCBreakpointSubroutineLoop
		NOT ax
		NOT dx
		PUSH dx
		PUSH ax
		POP eax

		RET
	TestCRCBreakpointSubroutine ENDP
@TestCRCBreakpoint:
    PUSH OFFSET @TestCRCBreakpointSehExit
    ASSUME fs:nothing
    PUSH DWORD PTR fs:[0h]
    MOV fs:[0], esp
    LEA esi, CRC_Table
    LEA edi, OFFSET @TestCRC_StartMarker
    MOV ecx, 020h    ; check 0x20 bytes
    CALL TestCRCBreakpointSubroutine
    MOV [dwCRC32result], eax
    PUSH OFFSET szReportFormatHexWW
    PUSH [dwCRC32result]
    PUSH OFFSET szCRCresult
    CALL printDwordFormatted
    MOV eax, [dwCRC32result]
    CMP DWORD PTR CRC, eax
    JNZ @TestCRCBreakpointFailed
        @TestCRCBreakpointSehExit:
        MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
        POP DWORD PTR fs:[0]
        ADD esp, 4
        POP ebp

        RET
@TestCRCBreakpointFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; use CreateFile on own executable with exclusive access desired to create
; a collision with a handle a debugger might hold on the file.

@IntroCreateFile:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szCreateFileTitle
PUSH OFFSET szCreateFileRef
PUSH OFFSET szCreateFileText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCreateFile:
XOR ebx, ebx
MOV eax, OFFSET CreateFileLabel
PUSH 104h    ; MAX_PATH
PUSH eax
PUSH ebx    ; self filename
CALL GetModuleFileNameA
MOV eax, OFFSET CreateFileLabel
PUSH ebx
PUSH ebx
PUSH 3    ; OPEN_EXISTING
PUSH ebx
PUSH ebx
PUSH 80000000h    ; GENERIC_READ
PUSH eax
CALL CreateFileA
INC eax
JE @TestCreateFileFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestCreateFileFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; RaiseException() with an exception that the debugger consumes (silently)

@IntroRaiseException:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRaiseExceptionTitle
PUSH OFFSET szRaiseExceptionRef
PUSH OFFSET szRaiseExceptionText
CALL storeAndPrintTestTitle

NOP
NOP

@TestRaiseException:
PUSH OFFSET @TestRaiseExceptionExit
ASSUME fs:nothing
PUSH fs:[0]
MOV fs:[0], esp
MOV [dwSavedStackPointer], esp
XOR eax, eax
PUSH eax
PUSH eax
PUSH eax
PUSH 40010007h    ; DBG_CONTROL_C
CALL RaiseException
JMP @TestRaiseExceptionFailed
	@TestRaiseExceptionExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP fs:[0]
    ADD esp, 4
    POP ebp

    RET
@TestRaiseExceptionFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; LoadLibrary() executed by debugger keeps handle to the library, it can
; afterwards not be opened for exclusive access

@IntroLoadLibrary:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szLoadLibraryTitle
PUSH OFFSET szLoadLibraryRef
PUSH OFFSET szLoadLibraryText
CALL storeAndPrintTestTitle

NOP
NOP

@TestLoadLibrary:
PUSH OFFSET @TestLoadLibrarySehExit
ASSUME fs:nothing
PUSH fs:[0]
MOV fs:[0], esp
MOV [dwSavedStackPointer], esp
CALL GetVersion
CMP al, 06h
JB @TestLoadLibraryAborted
	LEA esi, szWs2_32Dll
	PUSH esi
	CALL LoadLibraryA
	PUSH eax
	CALL FreeLibrary
	XOR ebx, ebx
	PUSH ebx
	PUSH ebx
	PUSH 3
	PUSH ebx
	PUSH ebx
	PUSH 80000000h
	PUSH esi
	CALL CreateFileA
	INC eax
	JE @TestLoadLibraryFailed
		@TestLoadLibrarySehExit:
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		MOV esp, [dwSavedStackPointer]
		POP fs:[0]
		ADD esp, 4
		POP ebp

		RET
    @TestLoadLibraryFailed:
    MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
    MOV esp, [dwSavedStackPointer]
    POP fs:[0]
    ADD esp, 4
    POP ebp

    RET
@TestLoadLibraryAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Int 2d exception without debugger

@IntroInt2d:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInt2dTitle
PUSH OFFSET szInt2dRef
PUSH OFFSET szInt2dText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH OFFSET @TestInt2dSehExit
ASSUME fs:nothing
PUSH DWORD PTR fs:[0h]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
XOR eax, eax
INT 2dh
JMP @TestInt2dFailed
    @TestInt2dSehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestInt2dFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Ctrl + C manually performed. Breaks Keyboard Interrupts but issues an
; exception many debuggers will consume


@IntroCtrlC:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szCtrlCTitle
PUSH OFFSET szCtrlCRef
PUSH OFFSET szCtrlCText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCtrlC:
ASSUME fs:nothing
PUSH OFFSET @TestCtrlCSeh
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH 1
PUSH @TestCtrlCSehExit
CALL SetConsoleCtrlHandler
PUSH 0
PUSH CTRL_C_EVENT
CALL GenerateConsoleCtrlEvent
PUSH 1000
CALL Sleep
@TestCtrlCSeh:
JMP @TestCtrlCFailed
	@TestCtrlCSehExit:
	MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
	MOV esp, [dwSavedStackPointer]
	POP DWORD PTR fs:[0]
	ADD esp,4
	POP ebp

	RET
@TestCtrlCFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; CALL upon POP to obtain the current Instruction Pointer,
; a classic trick used in position independent code.

@IntroCallPop:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szCallPopTitle
PUSH OFFSET szCallPopRef
PUSH OFFSET szCallPopText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCallPop:
CALL $ + 5
@TestCallPopAfterCall:
POP edx
MOV [dwIpAddress], edx
PUSH OFFSET szReportFormatHexWW
PUSH [dwIpAddress]
PUSH OFFSET szIpAddress
CALL printDwordFormatted
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; SEH-based Get IP variant of above code

@IntroSehGetIp:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szSehGetIpTitle
PUSH OFFSET szSehGetIpRef
PUSH OFFSET szSehGetIpText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @TestSehGetIpSeh
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
XOR EAX, EAX
@TestSehGetIpExceptionReason:
IDIV EAX    ; divide by zero to cause an exception
@TestSehGetIpSeh:
MOV EAX, dword ptr ds:[esp+4h]
MOV EAX, dword ptr ds:[eax+0Ch]
MOV [dwIpAddress], eax
PUSH OFFSET szReportFormatHexWW
PUSH [dwIpAddress]
PUSH OFFSET szIpAddress
CALL printDwordFormatted
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]    ; restore old SEH
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; FPU based variant of above code

@IntroFPU:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szFPUTitle
PUSH OFFSET szFPURef
PUSH OFFSET szFPUText
CALL storeAndPrintTestTitle

NOP
NOP

@TestFPU:
@TestFPU_FPU:
FNOP
FNSTENV [fpuenv_store]
MOV edx,[fpuenv_store.InstructionPointer]
MOV [dwIpAddress], edx
PUSH OFFSET szReportFormatHexWW
PUSH [dwIpAddress]
PUSH OFFSET szIpAddress
CALL printDwordFormatted
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; INT 2e / INT 2c variant of above code (32 bit systems)
; int 2c fails on Vista+

@IntroInt2e:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInt2eTitle
PUSH OFFSET szInt2eRef
PUSH OFFSET szInt2eText
CALL storeAndPrintTestTitle

NOP
NOP

@TestInt02eh:
MOV ax, gs
TEST ax, ax
JNZ @TestInt2e_Aborted
	ASSUME fs:nothing
	PUSH OFFSET @TestInt2e_SehExit
	PUSH DWORD PTR fs:[0]
	MOV fs:[0],esp
	MOV [dwSavedStackPointer], esp
	XOR eax, eax
	INT 02Eh
	MOV [dwIpAddress], edx
	PUSH OFFSET szReportFormatHexWW
	PUSH [dwIpAddress]
	PUSH OFFSET szIpAddress
	CALL printDwordFormatted
	CALL GetVersion
	CMP al, 5
	JA @TestInt2e_SehExit
		XOR eax, eax
		INT 02Ch
		MOV [dwIpAddress], edx
		PUSH OFFSET szReportFormatHexWW
		PUSH [dwIpAddress]
		PUSH OFFSET szIpAddress
		CALL printDwordFormatted
	@TestInt2e_SehExit:
	MOV esp, [dwSavedStackPointer]
	POP DWORD PTR fs:[0]
	ADD esp,4
	POP ebp

	RET
@TestInt2e_Aborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Anti Stepping, through manipulation of GS register

@IntroAntiStepping:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szAntiSteppingTitle
PUSH OFFSET szAntiSteppingRef
PUSH OFFSET szAntiSteppingText
CALL storeAndPrintTestTitle

NOP
NOP

@TestAntiStepping:
PUSH 3
POP GS
@AS_LOOP:
MOV ax, gs
CMP al, 3
JE @AS_LOOP
PUSH 3
	POP gs
	MOV ax, gs
	cmp al, 3
	JNZ @TestAntiSteppingFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestAntiSteppingFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Breakpoint Rewrite Anti Stepping

@IntroRewriteAntiStepping:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRewriteAntiSteppingTitle
PUSH OFFSET szRewriteAntiSteppingRef
PUSH OFFSET szRewriteAntiSteppingText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @TestRASSeh
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
MOV al, 90h
XOR ecx, ecx
INC ecx
MOV edi, @RASNextInstr
REP STOSB
@RASNextInstr:
NOP
NOP
INT 03h
@TestRASSeh:
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; SEH Tests demonstrate different ways to trigger exceptions and the
; impact on the reported exception address

@IntroSeh:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szSehTitle
PUSH OFFSET szSehRef
PUSH OFFSET szSehText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH @TestSeh1_SehExit
PUSH DWORD PTR fs:[0]
MOV DWORD PTR fs:[0], esp
MOV [dwSavedStackPointer], esp
XOR eax, eax
INT 2dh
@TestSeh1_AfterInt:
JMP @TestSeh1_AfterSeh
	NOP
	NOP
	NOP
	NOP
	@TestSeh1_SehExit:
	MOV eax, DWORD PTR ds:[esp + 0ch]
	CMP DWORD PTR ds:[eax + 0b8h], @TestSeh1_AfterInt
JNZ @TestSeh1_AfterSeh
    MOV eax, OFFSET szSubtestSuccessfulMessage
    CALL printSubtestSuccessful
	MOV esp, [dwSavedStackPointer]
	POP fs:[0]
	ADD esp, 4
	JMP @TestSeh_Status

@TestSeh1_AfterSeh:
MOV eax, OFFSET szSubtestFailedMessage
CALL printSubtestFailed
MOV esp, [dwSavedStackPointer]
POP fs:[0]
ADD esp, 4

NOP
NOP


; -------------------------------------------------------------------------
; complete test - print message failed if one ore more tests failed

@TestSeh_Status:
CMP [dwSehTestFailCounter], 0
JNE @TestSeh_Failed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestSeh_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; DeleteFiber - GetLastError: distinction of error in debugged case

@IntroDeleteFiber:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szDeleteFiberTitle
PUSH OFFSET szDeleteFiberRef
PUSH OFFSET szDeleteFiberText
CALL storeAndPrintTestTitle

NOP
NOP

@TestDeleteFiber:
CALL GetVersion
CMP al, 05h
JA @TestDeleteFiberAborted
	PUSH start
	CALL DeleteFiber
	CALL GetLastError
	CMP eax, 57h
	JNZ @TestDeleteFiberFailed
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		POP ebp

		RET
	@TestDeleteFiberFailed:
	MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
	POP ebp

	RET
@TestDeleteFiberAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
POP ebp

RET

M_insert_16_NOPs


; #########################################################################
; using CloseHandle() on invalid handle annoys massively when debugging

@IntroCloseHandle:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szCloseHandleTitle
PUSH OFFSET szCloseHandleRef
PUSH OFFSET szCloseHandleText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCloseHandle:
ASSUME fs:nothing
PUSH OFFSET @TestCloseHandleSehTrap
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH esp
CALL CloseHandle
JMP @TestCloseHandleSuccess
	@TestCloseHandleSehTrap:
	MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
	MOV esp, [dwSavedStackPointer]
	POP DWORD PTR fs:[0]
	ADD esp,4
	POP ebp

	RET
@TestCloseHandleSuccess:
MOV eax, OFFSET szTestSuccessfulMessage
CALL printTestSuccessful
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; NtQueryInformationProcess -> ProcessDebugFlags

@IntroDebugInherit:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szDebugInheritTitle
PUSH OFFSET szDebugInheritRef
PUSH OFFSET szDebugInheritText
CALL storeAndPrintTestTitle

NOP
NOP

@TestDebugInherit:
SUB esp, 4
MOV ebx, esp
PUSH 0
PUSH 4
PUSH ebx
PUSH 01fh
PUSH -1
CALL NtQueryInformationProcess
POP eax
TEST eax, eax
JE @TestDebugInheritFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestDebugInheritFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; NtQueryInformationProcess -> ProcessDebugObjectHandle

@IntroDebugObjectHandle:
PUSH ebp
MOV ebp, esp
PUSH OFFSET szDebugObjectHandleTitle
PUSH OFFSET szDebugObjectHandleRef
PUSH OFFSET szDebugObjectHandleText
CALL storeAndPrintTestTitle

NOP
NOP

@TestDebugObjectHandle:
SUB esp, 4
MOV ebx, esp
PUSH 0
PUSH 4
PUSH ebx
PUSH 01eh
PUSH -1
CALL NtQueryInformationProcess
POP eax
TEST eax, eax
JNE @TestDebugObjectHandleFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestDebugObjectHandleFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################-
; SetLastError/DebugString (can crash older version of OllyDbg)

@IntroSetLastError:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szSetLastErrorTitle
PUSH OFFSET szSetLastErrorRef
PUSH OFFSET szSetLastErrorText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSetLastError:
CALL GetVersion
CMP al, 05h
JA @TestSetLastErrorAborted
	ASSUME fs:nothing
	PUSH OFFSET @TestSetLastErrorSehExit
	PUSH DWORD PTR fs:[0]
	MOV fs:[0], esp
	MOV [dwSavedStackPointer], esp
	PUSH 0C0000005h
	CALL SetLastError
	PUSH OFFSET [szSetLastErrorDebugString]
	CALL OutputDebugStringA
	CMP dword ptr fs:[34h], 0
	CALL GetLastError
	mov [dwIpAddress], eax
	CMP eax, 0C0000005h
	JE @TestSetLastErrorFailed
		@TestSetLastErrorSehExit:
		PUSH OFFSET szReportFormatHexWW
		PUSH [dwIpAddress]
		PUSH OFFSET szSetLastErrorCode
		CALL printDwordFormatted
		MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
		MOV esp, [dwSavedStackPointer]
		POP DWORD PTR fs:[0]
		ADD esp, 4
		POP ebp

		RET
	@TestSetLastErrorFailed:
	MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
	MOV esp, [dwSavedStackPointer]
	POP DWORD PTR fs:[0]
	ADD esp, 4
	POP ebp

	RET

@TestSetLastErrorAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
;  Use SetInformationThread with ThreadInformationClass->ThreadHideFromDebugger

@IntroSetInformationThread:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szSetInformationThreadTitle
PUSH OFFSET szSetInformationThreadRef
PUSH OFFSET szSetInformationThreadText
CALL storeAndPrintTestTitle

NOP
NOP

@TestSetInformationThread:
PUSH 0
PUSH 0
PUSH 011h
PUSH -2
CALL NtSetInformationThread
TEST eax, eax
JNE @TestSetInformationThreadFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestSetInformationThreadFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Can Open CSRSS.exe - needs SE_DEBUG_PRIVILEGE that is acquired by some
; debuggers. Weak indicator for a debugger.

@IntroCanOpenCsrss:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szCanOpenCsrssTitle
PUSH OFFSET szCanOpenCsrssRef
PUSH OFFSET szCanOpenCsrssText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCanOpenCsrss:
CALL CsrGetProcessId
PUSH eax
PUSH 0
PUSH 01F0FFFh
CALL OpenProcess
TEST eax, eax
JNE @TestCanOpenCsrssFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestCanOpenCsrssFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; ParentProcessId == Explorer PID? (only valid when started directly,
; not from cmdline etc.)

@IntroParentProcessId:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szParentProcessIdTitle
PUSH OFFSET szParentProcessIdRef
PUSH OFFSET szParentProcessIdText
CALL storeAndPrintTestTitle

NOP
NOP

@TestParentProcessId:
CALL GetShellWindow
SUB esp, 4
MOV ebx, esp
PUSH ebx
PUSH eax
CALL GetWindowThreadProcessId ; results remains on stack for later evaluation
SUB esp, 018h
MOV ebx, esp
PUSH 0
PUSH 018h
PUSH ebx
PUSH 0
PUSH -1
CALL NtQueryInformationProcess ; ParentPID is returned in 6th dword of Process Basic Information
ADD esp, 014h
POP edx
POP eax
CMP eax, edx
JNE @TestParentProcessIdFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestParentProcessIdFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; BlockInput disable Keyboard & Mouse of debugging process

@IntroBlockInput:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szBlockInputTitle
PUSH OFFSET szBlockInputRef
PUSH OFFSET szBlockInputText
CALL storeAndPrintTestTitle

NOP
NOP

@TestBlockInput:
PUSH 1
CALL BlockInput
MOV eax, OFFSET szTestSuccessfulMessage
CALL printTestSuccessful
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Dynamically increase SizeOfImage in PEB to confuse debuggers when
; attaching and disable some dumping tools (such as LordPE)

@IntroDynamicLargeSizeOfImage:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szDynamicLargeSizeOfImageTitle
PUSH OFFSET szDynamicLargeSizeOfImageRef
PUSH OFFSET szDynamicLargeSizeOfImageText
CALL storeAndPrintTestTitle

NOP
NOP

@TestDynamicLargeSizeOfImage:
ASSUME fs:nothing
MOV eax, DWORD PTR fs:[30h]    ; PEB
MOV eax, DWORD PTR [eax + 0Ch]    ; PEB_LDR_DATA
MOV eax, DWORD PTR [eax + 0Ch]    ; InOrderModuleList
MOV DWORD PTR [eax + 20h], 10000000h    ; SizeOfImage
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Virtual Machine Detection through SLDT

@IntroVmSLDT:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmSldtTitle
PUSH OFFSET szVmSldtRef
PUSH OFFSET szVmSldtText
CALL storeAndPrintTestTitle

NOP
NOP

SLDT sldtTable
MOV ax, WORD PTR [sldtTable + 0]
TEST ax, ax
JNZ @Test_VM_SLDT_Failed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET

@Test_VM_SLDT_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Virtual Machine Detection through SIDT

@IntroVmSIDT:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmSidtTitle
PUSH OFFSET szVmSidtRef
PUSH OFFSET szVmSidtText
CALL storeAndPrintTestTitle

NOP
NOP

SIDT sidtTable
XOR eax, eax
MOV eax, DWORD PTR [sidtTable + 5]
CMP eax, 0D0h
JGE @Test_VM_SIDT_Failed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET

@Test_VM_SIDT_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Virtual Machine Detection through SGDT

@IntroVmSGDT:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmSgdtTitle
PUSH OFFSET szVmSgdtRef
PUSH OFFSET szVmSgdtText
CALL storeAndPrintTestTitle

NOP
NOP

SGDT sgdtTable
XOR eax, eax
MOV eax, DWORD PTR [sgdtTable + 5]
CMP eax, 0D0h
JGE @Test_VM_SGDT_Failed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET

@Test_VM_SGDT_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; trigger Magic Number "VMXh" for the VMware interface

@IntroVmMagicNumberVMware:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmMagicNumberVMwareTitle
PUSH OFFSET szVmMagicNumberVMwareRef
PUSH OFFSET szVmMagicNumberVMwareText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @Test_VM_MagicNumberVMware_SehExit
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
MOV eax, 'VMXh'    ; Magic
MOV ebx, 0    ; ebx to a value unequal VMXh
MOV ecx, 10    ; option: read version of VM Ware
MOV edx, 'VX'    ; Magic
IN eax, dx    ; read from port

CMP ebx, 'VMXh'    ; answer in ebx reads VMXh if it is a VM Ware system
JE @Test_VM_MagicNumberVMware_Failed
    @Test_VM_MagicNumberVMware_SehExit:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@Test_VM_MagicNumberVMware_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; variant for parallels

@IntroVmMagicNumberParallels:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmMagicNumberParallelsTitle
PUSH OFFSET szVmMagicNumberParallelsRef
PUSH OFFSET szVmMagicNumberParallelsText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @Test_VM_MagicNumberParallels_SehExit
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH ebx
PUSH esi
MOV eax, 13h    ; function code?
MOV ebx, 3141h    ; magic number
MOV esi, 1h    ; sub function code?
MOV dx, 0e4h
IN eax, dx    ; read from port
CMP eax, 3141h    ; make sure eax remained as magic
JNE @done
    CMP ebx, 3141h    ; ensure ebx is changed
    JE @done
    TEST ebx, ebx    ; make sure build number is non-zero
    JE @Test_VM_MagicNumberParallels_Failed
        @done:
        POP esi
        POP ebx
        @Test_VM_MagicNumberParallels_SehExit:
        MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
        MOV esp, [dwSavedStackPointer]
        POP DWORD PTR fs:[0]
        ADD esp,4
        POP ebp

    RET
@Test_VM_MagicNumberParallels_Failed:
POP esi
POP ebx
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; variant for VirtualPC

@IntroVmMagicNumberVirtualPC:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szVmMagicNumberVirtualPcTitle
PUSH OFFSET szVmMagicNumberVirtualPcRef
PUSH OFFSET szVmMagicNumberVirtualPcText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @Test_VM_MagicNumberVirtualPC_SehExit
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH ebx
MOV ebx, 0
MOV eax, 1
DB 0Fh, 3Fh, 07h, 0Bh
TEST ebx, ebx
XOR eax, eax
POP ebx
JE @Test_VM_MagicNumberVirtualPC_Failed
    PUSH ebx
    MOV ebx, 0
    MOV eax, 1
    DB 0Fh, 0C7h, 0C8h, 01h, 00h
    TEST ebx, ebx
    XOR eax, eax
    POP ebx
    JE @Test_VM_MagicNumberVirtualPC_Failed
	@Test_VM_MagicNumberVirtualPC_SehExit:
	MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
	MOV esp, [dwSavedStackPointer]
	POP DWORD PTR fs:[0]
	ADD esp,4
	POP ebp

	RET
@Test_VM_MagicNumberVirtualPC_Failed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; use RtlQueryProcessHeapInformation() to identify debugging options

@IntroRtlQueryProcessHeapInformation:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRtlQueryProcessHeapInformationTitle
PUSH OFFSET szRtlQueryProcessHeapInformationRef
PUSH OFFSET szRtlQueryProcessHeapInformationText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH 0
PUSH 0
CALL RtlCreateQueryDebugBuffer
PUSH eax
XCHG ebx, eax
CALL RtlQueryProcessHeapInformation
MOV eax, [ebx+38h]    ; HeapInformation
MOV eax, [eax+8]     ; Flags
AND eax, 0effeffffh    ; neither CREATE_ALIGN_16 nor HEAP_SKIP_VALIDATION_CHECKS
CMP eax, 40000062h    ; GROWABLE + TAIL_CHECKING_ENABLED + FREE_CHECKING_ENABLED + VALIDATE_PARAMETERS_ENABLED
JE @TestRtlQueryProcessHeapInformationFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestRtlQueryProcessHeapInformationFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; variant of the above with RtlQueryProcessDebugInformation()

@IntroRtlQueryProcessDebugInformation:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRtlQueryProcessDebugInformationTitle
PUSH OFFSET szRtlQueryProcessDebugInformationRef
PUSH OFFSET szRtlQueryProcessDebugInformationText
CALL storeAndPrintTestTitle

NOP
NOP

XOR ebx, ebx
PUSH ebx
PUSH ebx
CALL RtlCreateQueryDebugBuffer
PUSH eax
XCHG ebx, eax
PUSH 14h    ; PDI_HEAPS + PDI_HEAP_BLOCKS
PUSH dword ptr fs:[eax+20h]     ; UniqueProcess
CALL RtlQueryProcessDebugInformation
MOV eax, [ebx+38h]    ; HeapInformation
MOV eax, [eax+8]    ; Flags
and eax, 0effeffffh    ; neither CREATE_ALIGN_16 nor HEAP_SKIP_VALIDATION_CHECKS
cmp eax, 40000062h    ; GROWABLE + TAIL_CHECKING_ENABLED + FREE_CHECKING_ENABLED + VALIDATE_PARAMETERS_ENABLED
JE @TestRtlQueryProcessDebugInformationFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestRtlQueryProcessDebugInformationFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; RtlProcessFlsData execution take-over from debugger

@IntroRtlProcessFlsData:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szRtlProcessFlsDataTitle
PUSH OFFSET szRtlProcessFlsDataRef
PUSH OFFSET szRtlProcessFlsDataText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
PUSH OFFSET @TestRtlProcessFlsDataFailed
PUSH DWORD PTR fs:[0]
MOV fs:[0],esp
MOV [dwSavedStackPointer], esp
PUSH offset szNtdll    ; load function pointer to ntdll.RtlProcessFlsData dynamically
CALL LoadLibraryA
PUSH offset szRtlProcessFlsDataName
PUSH eax
CALL GetProcAddress
TEST eax, eax    ; technique can not be performed on this system
JZ @TestRtlProcessFlsDataAborted
    PUSH eax
    PUSH 30h
    POP eax
    MOV ecx, fs:[eax]
    MOV ah, 2
    INC dword ptr [ecx+eax-4h]    ; must be at least 1
    MOV esi, offset ddRtlProcessFlsDataStructure - 4h
    PUSH EDX
    MOV edx, ecx
    ADD edx, eax
    SUB edx, 24h
    MOV [ddRtlProcessFlsDataOverwriteAddress], edx
    MOV edx, [ddRtlProcessFlsDataOverwriteAddress]
    MOV [ddRtlProcessFlsDataOverwriteValue], edx
    POP EDX
    MOV [ecx+eax-24h], esi
    LODSD
    POP eax    ; get function pointer to RtlProcessFlsData, previously saved

    PUSH esi
    CALL eax
    JMP @TestRtlProcessFlsDataFailed
	    @RtlProcessFlsDataSuccess:
	    MOV eax, OFFSET szTestSuccessfulMessage
        CALL printTestSuccessful
        PUSH edx
        MOV edx, [ddRtlProcessFlsDataOverwriteAddress]
        MOV eax, [ddRtlProcessFlsDataOverwriteValue]
        MOV [edx], eax
        POP edx
	    MOV esp, [dwSavedStackPointer]
	    POP DWORD PTR fs:[0]
	    ADD esp,4
	    POP ebp

	    RET
    @TestRtlProcessFlsDataFailed:
    MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
    PUSH edx
    MOV edx, [ddRtlProcessFlsDataOverwriteAddress]
    MOV eax, [ddRtlProcessFlsDataOverwriteValue]
    MOV [edx], eax
    POP edx
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestRtlProcessFlsDataAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; Exception-based Instruction Counting

@IntroInstructionCounting:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInstructionCountingTitle
PUSH OFFSET szInstructionCountingRef
PUSH OFFSET szInstructionCountingText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
; TODO: test 32bit
mov ax, gs
test ax, ax
JNZ @TestInstructionCountingAborted
    xor eax, eax
    push offset @TestInstructionCountingExceptionHandler
    push dword ptr fs:[0]
    mov fs:[0], esp
    MOV [dwSavedStackPointer], esp
    int 3    ; force exception to occur
    @TestInstructionCountingDummyInstr: 
    nop
    l2: 
    nop
    l3: 
    nop
    l4: 
    nop
    cmp al, 4
    jne @TestInstructionCountingFailed
	    MOV eax, OFFSET szTestSuccessfulMessage
          CALL printTestSuccessful
	    MOV esp, [dwSavedStackPointer]
	    POP DWORD PTR fs:[0]
	    ADD esp,4
	    POP ebp

	    RET
    @TestInstructionCountingFailed:
    MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
    MOV esp, [dwSavedStackPointer]
    POP DWORD PTR fs:[0]
    ADD esp, 4
    POP ebp

    RET
@TestInstructionCountingAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP DWORD PTR fs:[0]
ADD esp,4
POP ebp

RET

M_insert_4_NOPs

@TestInstructionCountingExceptionHandler: 
push edi
mov eax, [esp+8]    ; ExceptionRecord
mov edi, [esp+10h]    ; ContextRecord
push 55h    ; local-enable DR0, DR1, DR2, DR3
pop ecx
inc dword ptr ds:[ecx*2+edi+0eh]    ; Eip
mov eax, [eax]    ; ExceptionCode
sub eax, 80000003h    ;EXCEPTION_BREAKPOINT
jne @TestInstructionCountingCheckSingleStep
mov eax, offset @TestInstructionCountingDummyInstr
scasd
stosd    ; Dr0
inc eax    ; l2
stosd    ; Dr1
inc eax    ; l2
stosd    ; Dr2
inc eax    ; l4
stosd    ; Dr3
; local-enable breakpoints
; for compatibility with old CPUs
mov ch, 1
xchg ecx, eax
scasd
stosd    ; Dr7
xor eax, eax
pop edi
ret

@TestInstructionCountingCheckSingleStep: 
dec eax ;EXCEPTION_SINGLE_STEP
jne @TestInstructionCountingFailed
inc byte ptr ds:[ecx*2+edi+6] ;Eax
pop edi
ret

M_insert_16_NOPs

; #########################################################################
; use ToolHelp32ReadProcessMemory() to find breakpoint on next instruction

@IntroToolHelp32ReadProcessMemory:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szToolHelp32ReadProcessMemoryTitle
PUSH OFFSET szToolHelp32ReadProcessMemoryRef
PUSH OFFSET szToolHelp32ReadProcessMemoryText
CALL storeAndPrintTestTitle

NOP
NOP

PUSH eax
MOV eax, esp
XOR ebx, ebx
PUSH ebx
INC ebx
PUSH ebx
PUSH eax
PUSH offset @TestToolHelp32ReadProcessMemory_NextInstruction
PUSH dword ptr fs:[ebx+1fh]    ; own PID
CALL Toolhelp32ReadProcessMemory
@TestToolHelp32ReadProcessMemory_NextInstruction:
POP eax
CMP al, 0cch
JE @TestToolHelp32ReadProcessMemoryFailed
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET
@TestToolHelp32ReadProcessMemoryFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; CreateToolhelp32Snapshot()

@IntroCreateToolhelp32Snapshot:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szCreateToolhelp32SnapshotTitle
PUSH OFFSET szCreateToolhelp32SnapshotRef
PUSH OFFSET szCreateToolhelp32SnapshotText
CALL storeAndPrintTestTitle

NOP
NOP

@TestCreateToolhelp32Snapshot:
XOR esi, esi
XOR edi, edi
PUSH esi
PUSH 2    ; TH32CS_SNAPPROCESS
CALL CreateToolhelp32Snapshot
MOV ebx, offset lpProcessEntry32
XCHG ebp, eax
@TestCt32sStartEnum:
    PUSH ebx
    PUSH ebp
    CALL Process32First
    @TestCt32sCheckProcess:
        MOV eax, fs:[eax+1fh]    ; UniqueProcess
        CMP [ebx+8], eax     ; PROCESSENTRY32.th32ProcessID
        JNE @TestCt32sNotOwnProcess
            MOV edi, [ebx+18h]     ; PROCESSENTRY32.th32ParentProcessID
        @TestCt32sNotOwnProcess:
        TEST edi, edi
        JE @TestCt32sOwnParentPidUnknown
            CMP esi, edi
            JE @TestCt32sParentFound
        @TestCt32sOwnParentPidUnknown:
        LEA ecx, [ebx + 24h]     ; PROCESSENTRY32.szExeFile
        PUSH esi
        MOV esi, ecx
        @Ct32sExtractLowerCaseExeName:
        LODSB
        CMP al, "\"
        JNE @TestC32sNotBackslash
            MOV ecx, esi
        @TestC32sNotBackslash:
        OR byte ptr [esi-1], " "
        TEST al, al
        JNE @Ct32sExtractLowerCaseExeName
            SUB esi, ecx
            XCHG ecx, esi
            PUSH edi
            MOV edi, offset szExplorerExe
            REPE CMPSB
            POP edi
            POP esi
        JNE @TestCt32sEnumNext
            TEST esi, esi
            JE @Ct32sFoundExplorerForFirstTime
                MOV esi, offset lpCt32sCounters
                CMP cl, [esi]
                ADC [esi], ecx
            @Ct32sFoundExplorerForFirstTime:
            MOV esi, [ebx+8] ;th32ProcessID
        @TestCt32sEnumNext:
        PUSH ebx
        PUSH ebp
        CALL Process32Next
        TEST eax, eax
    JNE @TestCt32sCheckProcess
    DEC byte ptr [lpCt32sCounters + 1]
JNE @TestCt32sStartEnum
JMP @TestCreateToolhelp32SnapshotFailed
    @TestCt32sParentFound:
    MOV eax, OFFSET szTestSuccessfulMessage
    CALL printTestSuccessful
    POP ebp

    RET

@TestCreateToolhelp32SnapshotFailed:
MOV eax, OFFSET szTestFailedMessage
CALL printTestFailed
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; When a process is debugged on Vista, its main thread TEB, at offset 0xBFC,
; contains a pointer to a unicode string referencing a system dll.
; Moreover, the string follows this pointer (therefore, located at OFFSET 0xC00 in the TEB).
; If the process is not debugged, the pointer is set to NULL and the string is not present.

@IntroWindowsVistaDebugger:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szWindowsVistaDebuggerTitle
PUSH OFFSET szWindowsVistaDebuggerRef
PUSH OFFSET szWindowsVistaDebuggerText
CALL storeAndPrintTestTitle

NOP
NOP

@TestWindowsVistaDebugger:
ASSUME fs:nothing
PUSH OFFSET @TestWindowsVistaDebuggerSehExit
PUSH DWORD PTR fs:[0h]
MOV fs:[0], esp
MOV DWORD PTR ds:[dwSavedStackPointer], esp
CALL GetVersion
CMP ax, 0006h
JNE @TestWindowsVistaDebuggerAborted
    MOV eax, fs:[18h]
    ADD eax, 0BFCh
    MOV ebx, [eax]
    TEST ebx, ebx
    JE @TestWindowsVistaDebuggerExit
        SUB ebx, eax
        SUB ebx, 4
        JNE @TestWindowsVistaDebuggerExit
        JMP @TestWindowsVistaDebuggerFailed
            @TestWindowsVistaDebuggerSehExit:
            @TestWindowsVistaDebuggerExit:
            MOV eax, OFFSET szTestSuccessfulMessage

            CALL printTestSuccessful
            POP DWORD PTR fs:[0]
            ADD esp,4
            POP ebp

            RET
    @TestWindowsVistaDebuggerFailed:
    MOV eax, OFFSET szTestFailedMessage
    CALL printTestFailed
    POP DWORD PTR fs:[0]
    ADD esp,4
    POP ebp

    RET
@TestWindowsVistaDebuggerAborted:
MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
MOV esp, [dwSavedStackPointer]
POP fs:[0]
ADD esp, 4
POP ebp

RET

M_insert_16_NOPs


; #########################################################################
; use int 2e for code redirection on 32bit Vista+ via KernelCallbackTable

@IntroInt2eRedirect:
PUSH ebp
MOV ebp, esp

PUSH OFFSET szInt2eRedirectTitle
PUSH OFFSET szInt2eRedirectRef
PUSH OFFSET szInt2eRedirectText
CALL storeAndPrintTestTitle

NOP
NOP

ASSUME fs:nothing
CALL GetVersion
CMP al, 6
JB @TestInt2eRedirectAborted
    PUSH offset szKernel32Dll
    CALL GetModuleHandleA
    PUSH offset szIsWow64Process
    PUSH eax
    CALL GetProcAddress
    XCHG ecx, eax
    JECXZ @TestInt2eRedirectAborted
        PUSH eax
        PUSH esp
        PUSH -1
        CALL ecx
        POP ecx
        LOOP @TestInt2eRedirectAborted
            PUSH @TestInt2eRedirectFailed
            PUSH DWORD PTR fs:[0h]
            MOV fs:[0], esp
            MOV [dwSavedStackPointer], esp
            MOV eax, fs:[ecx + 30h]
            MOV dword ptr [eax + 2ch], offset lpFakeTable
            MOV dword ptr [lpFakeTable + 4 * 4ah], @Int2eRedirectSuccess
            MOV dword ptr [lpFakeTable + 4 * 4ch], @Int2eRedirectSuccess
            INT 2eh
            JMP @TestInt2eRedirectFailed
                @TestInt2eRedirectAborted:
                MOV eax, OFFSET szTestAbortedMessage
CALL printTestAborted
                POP ebp

                RET
                @Int2eRedirectSuccess:
                MOV eax, OFFSET szTestSuccessfulMessage
                CALL printTestSuccessful
                MOV esp, [dwSavedStackPointer]
                POP DWORD PTR fs:[0]
                ADD esp,4
                POP ebp

                RET
            @TestInt2eRedirectFailed:
            MOV eax, OFFSET szTestFailedMessage
            CALL printTestFailed
            MOV esp, [dwSavedStackPointer]
            POP DWORD PTR fs:[0]
            ADD esp,4
            POP ebp

            RET


M_insert_16_NOPs

; #########################################################################
; Finished - prepare summary

@Finish:
PUSH ebp
MOV ebp, esp

PUSH  OFFSET szFinishText
CALL antiRE_print
MOV [dwPrintTestTitle], 1
PUSH OFFSET szReportFormatIntWW
PUSH dwSuccessCounter
PUSH OFFSET szSuccessfulText
CALL printDwordFormatted
MOV [dwPrintTestTitle], 1
PUSH OFFSET szReportFormatIntWW
PUSH dwFailCounter
PUSH OFFSET szFailedText
CALL printDwordFormatted
MOV [execute_tls_test], 0    ; deactivate callback for end of program
POP ebp

RET

M_insert_16_NOPs

; #########################################################################
; add some additional room to play with ASM instructions

M_insert_16_NOPs
M_insert_16_NOPs
M_insert_16_NOPs
M_insert_16_NOPs

M_insert_16_NOPs
M_insert_16_NOPs
M_insert_16_NOPs
M_insert_16_NOPs

; #########################################################################
; #########################################################################



.code TLS_CB

; #########################################################################
; Prologue to inform the user of what is happening in the TLS callbacks

TLS_Prologue PROC hinstImg, fdwReason, lpvReserved
MOV eax, OFFSET szPrologue
MOV eax, OFFSET szPrologue_1
MOV eax, OFFSET szPrologue_2
MOV eax, OFFSET szPrologue_3
MOV eax, OFFSET szPrologue_4

RET

TLS_Prologue ENDP


M_insert_16_NOPs

; #########################################################################
; AntiDebugger TLS callback to check thread start address

TLS_NtQueryInformation PROC hinstImg, fdwReason, lpvReserved
    MOV eax, [execute_tls_test]
    test eax, eax
    JE @TestThreadLocalStorageSkipped
        @IntroThreadLocalStorage:
        PUSH OFFSET szThreadLocalStorageTitle
        PUSH OFFSET szThreadLocalStorageRef
        PUSH OFFSET szThreadLocalStorageText
        CALL storeAndPrintTestTitle

        NOP
        NOP

        PUSH eax
        MOV eax, esp
        PUSH 0
        PUSH 4
        PUSH eax
        PUSH 9 ; ThreadQuerySetWin32StartAddress
        PUSH -2 ;GetCurrentThread()
        CALL NtQueryInformationThread
        POP eax
        CMP eax, offset @TestThreadLocalStorageEnd
        JNB @TestThreadLocalStorageFailed
            @TestThreadLocalStorageEnd:
            MOV eax, OFFSET szTestSuccessfulMessage
            CALL printTestSuccessful

            RET

            @TestThreadLocalStorageFailed:
            MOV eax, OFFSET szTestFailedMessage
            CALL printTestFailed

    @TestThreadLocalStorageSkipped:

    RET

TLS_NtQueryInformation ENDP

M_insert_16_NOPs

; #########################################################################
; Setup: parsing of arguments and adjusting memory access rights

TLS_performSetup PROC hinstImg, fdwReason, lpvReserved
    MOV eax, OFFSET szSetup
    MOV eax, [setup_done]
    test eax, eax
    JNE @SetupDone
        MOV eax, OFFSET szParseArgs
        CALL parseCommandLineArguments
        MOV eax, OFFSET szMakeWritable
        CALL SetMemoryWritable
        MOV [setup_done], 1
        MOV [execute_tls_test], 1

    @SetupDone:

    RET

TLS_performSetup ENDP

M_insert_16_NOPs

; #########################################################################

tlsStart LABEL  DWORD
tlsEnd   LABEL  DWORD
@end_of_code:

END start
