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

// exait.cpp : Defines the entry point for the console application.
//

// eXait - eXtensible Anti-Instrumentation Tester v1.0
// by Francisco Falcon - Nahuel Riva

#include "stdafx.h"
#include "exait.h"

int _tmain(int argc, _TCHAR* argv[])
{

	PrintCredits();

	if(argc < 2)
	{
		PrintUsage();
		exit(EXIT_FAILURE);
	}
	else
	{
		if( strcmp(argv[1], "-l") == 0 )
		{
			// we must list all the available plugins
			printf("\nNumber of available plugins: %d\n", ListAvailablePlugins(GetPluginsFolder()));
		}
		else
		{
			if( strcmp(argv[1], "-p") == 0)
			{
				// we load the specified plugin
				if(argv[2] != NULL)
				{
					HMODULE hPlugin = LoadPlugin(argv[2]);
					
					ValidateResult(ExecutePlugin(hPlugin), CallGetPluginName(hPlugin));
				}
				else
				{
					printf("You MUST specify a plugin dll name! (i.e: detect_by_eip.dll)\n");
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				if( strcmp(argv[1], "-s") == 0 )
				{
					// we load the list of plugins
					int index = 2;
					while(argv[index] != NULL)
					{
						HMODULE hPlugin = LoadPlugin(argv[index]);
						ValidateResult(ExecutePlugin(hPlugin), CallGetPluginName(hPlugin));
						index++;
					}
				}
				else
				{
					if( strcmp(argv[1], "-h") == 0 )
					{
						system("cls");
						PrintUsage();
					}
					else
					{
						if( strcmp(argv[1], "-f") == 0)
						{
							if(argv[2] != NULL)
							{
								// we MUST load the plugins indicated in the specified file
								char line[MAX_PATH];
								FILE* fd = fopen(argv[2], "r");
								if(fd != NULL)
								{
									while(fgets(line, sizeof(line),fd) != NULL)
									{
										int len = strlen(line)-1;
										if(line[len] == '\n')
											line[len] = 0;

										HMODULE hPlugin = LoadPlugin(line);
										ValidateResult(ExecutePlugin(hPlugin), CallGetPluginName(hPlugin));
									}
								}
							}
							else
							{
								printf("You MUST specify a filename (i.e: blah.txt)!\n");
								exit(EXIT_FAILURE);
							}
						}
						else
						{
							if( strcmp(argv[1], "-a") == 0)
							{
								// we execute all the available plugins
								int cant = LoadPlugins(GetPluginsFolder());
								int i;
								for(i = 0; i < cant;i++)
									ValidateResult(ExecutePlugin(PluginArray[i]), CallGetPluginName(PluginArray[i]));
							}
							else
							{
								if( strcmp(argv[1], "-n") == 0)
								{
									if(argv[2] != NULL)
									{
										HMODULE hPlugin = LoadPlugin(argv[2]);
										printf("Plugin name: %s\n", CallGetPluginName(hPlugin)); 
									}
									else
									{
										printf("You MUST specify the plugin dll name (i.e: detect_by_eip.dll)\n");
										exit(EXIT_FAILURE);
									}
								}
								else
								{
									if( strcmp(argv[1], "-d") == 0)
									{
										if(argv[2] != NULL)
										{
											HMODULE hPlugin = LoadPlugin(argv[2]);
											printf("Plugin description: %s\n", CallGetPluginDescription(hPlugin));
										}
										else
										{
											printf("You MUST specify the plugin dll name (i.e: detect_by_eip.dll)\n");
											exit(EXIT_FAILURE);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return 0;
}