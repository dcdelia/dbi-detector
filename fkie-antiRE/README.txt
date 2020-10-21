###### License ############################################################ 
Published as open source under "BSD New" license

Copyright (c) 2011-2012, Daniel Plohmann
All rights reserved.

Redistribution and use in source and binary forms, 
with or without modification, 
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
 * The names of the authors may not be used to endorse or promote products 
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

###### Introduction #######################################################

Welcome to the interactive AntiRE Collection (June 15th, 2012)
created 2011/2012 by Daniel Plohmann and Christopher Kannen
contact: plohmann (at) cs (dot) uni-bonn (dot) de

 This tool summarizes trivially implemented versions of more or less common
 assembler code fragments with the goal to complicate the analysis of
 oftentimes malicious programs. Most tests aim at recognizing the presence
 of a debugger, detecting single-stepping or tracing, others modify memory
 dynamically, or allow detection of virtualized environments.
 Documentation on many of the techniques can be found in numerous places
 already. Our goal is to provide a collection of running code that is easily
 accessible to novice reverse engineers and can be directly used to experiment
 with these techniques, with intended use for educational purposes and to
 harden the own analysis environment against these mechanisms.

 We tried to limit the number of references for the tests to as few as
 possible in order to create a compact overview of related sources.
 The main inspirations and sources
 for many of the tests included in this project are:
 - Peter Ferrie's 'The Ultimate Anti-Debugging Reference' (PF-TUADR)
   (http://pferrie.host22.com/)
 - Ange Albertini's 'corkami' project (RE experiments and documentations)
   (http://code.google.com/p/corkami/)
 - 'The OpenRCE Anti RE Techniques Database', mainly driven by ap0x
   (http://www.openrce.org/reference_library/anti_reversing)
 - Nicolas Falliere's 'Windows Anti-Debug Reference'
   (http://www.symantec.com/connect/articles/windows-anti-debug-reference)
 - Joshua Jackon's 'Anti-Reverse Engineering Guide' implementations
   (http://tuts4you.com/download.php?view.2516)
 The remaining individual techniques are attributed to the source first
 identified while searching. If you have the feeling that you are missing
 in these credits, if you want to contribute to the project, or if you
 just want to provide us feedback, please fell free to contact us
 via the email address listed above!

###### Instructions #######################################################

Some of the code fragments in this tool may trigger signatures and 
heuristics as used e.g. by many anti-virus solutions. 
Because of this, we included the executables and source code in another 
zip-file, password-protected with the keyword "novirus".

The tool is intended to be used with a debugger. All individual tests 
will produce output on the console, giving a short explanation and 
showing the test result in the end. The tests are grouped by similar 
features and easily accessible via a "menu".

There are also some commandline options:
  -a   automated execution (without keyboard interrupts)
  -o   output report to file ./anti_re_output.log
  
This release contains two precompiled executables. The standard version 
requiring keys pressed to control the execution. The second version will 
only show failed/aborted tests and automatically create the report. It is
intended for easier use e.g. to test automated environments.

###### Final Words #######################################################

Many of the techniques implemented interact in a very special way with 
the operating system and can cause undesired effects. By using this tool,
we assume that you know what you are doing and you accept that you are 
using it on your own risk. As stated in the license, we will not take 
liability for any damage caused by this tool.
