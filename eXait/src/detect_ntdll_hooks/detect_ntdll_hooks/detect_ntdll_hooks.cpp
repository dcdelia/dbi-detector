/*
Copyright (c) 2012, Core Security Technologies
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

// detect_ntdll_hooks.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"


#define DllExport extern "C" __declspec(dllexport)
#define NOTDETECTED 0
#define DETECTED 1

DllExport char* GetPluginName();
DllExport char* GetPluginDescription();
DllExport int DoMyJob();


char* GetPluginName()
{
	static char PluginName[] = "Detect Pin by NTDLL hooks";
	return PluginName;
}



char* GetPluginDescription()
{
	static char MyDescription[] = "This plugin looks for hooks that Pin usually sets in four functions of NTDLL.dll.";
	return MyDescription;
}


int DoMyJob()
{
	LPVOID address;
	unsigned char firstbyte;
	int numberOfHooks = 0;
	char* functions[] = {"KiUserApcDispatcher", "KiUserCallbackDispatcher", "KiUserExceptionDispatcher", "LdrInitializeThunk"};
	int numberOfFunctions = sizeof(functions) / sizeof(functions[0]);

	for(int i=0; i < numberOfFunctions; i++)
	{
		address = (LPVOID)GetProcAddress(GetModuleHandle(L"ntdll.dll"), functions[i]);
		if (address)
		{
			firstbyte = *((unsigned char *)address);
			if (firstbyte == 0xE9){
				numberOfHooks++;
			}
		}
	}
	return numberOfHooks == numberOfFunctions? DETECTED: NOTDETECTED;
}