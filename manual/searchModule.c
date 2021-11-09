#include <windows.h>
#include <stdio.h>

// parsing code taken from https://github.com/arbiter34/GetProcAddress/

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#if 0
typedef struct _PEB_LDR_DATA {
	unsigned int		Length;
	unsigned int		Initialized;
	unsigned short		SsHandle;
	LIST_ENTRY			InLoadOrderModuleList;
	LIST_ENTRY			InMemoryOrderModuleList;
	void*				EntryInProgress;
	unsigned short		ShutdownInProgress;
	void*				ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
#else
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
#endif

typedef struct _PEB {
	BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
	PPEB_LDR_DATA		Ldr;
} PEB, *PPEB;

// Daniele's stuff

/*typedef struct _PEB_LDR_DATA64 {
  BYTE  ktm
  LIST_ENTRY64 InMemoryOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct_PEB64 {
    BYTE ktm[0x18];
    PPEB_LDR_DATA64     Ldr;
}*/

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#if 0
typedef struct _ACTIVATION_CONTEXT
{
	unsigned long       magic;
	int                 ref_count;
	//struct file_info    config;
	//struct file_info    appdir;
	struct assembly    *assemblies;
	unsigned int        num_assemblies;
	unsigned int        allocated_assemblies;
	/* section data */
	unsigned long       sections;
	struct strsection_header  *wndclass_section;
	struct strsection_header  *dllredirect_section;
	struct strsection_header  *progid_section;
	struct guidsection_header *tlib_section;
	struct guidsection_header *comserver_section;
	struct guidsection_header *ifaceps_section;
	struct guidsection_header *clrsurrogate_section;
} ACTIVATION_CONTEXT;
#endif

// 32-bit only
// PTIB GetTIB() {
// 	return (PTIB)__readfsdword(0x18);
// }

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks; /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
    LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
    PVOID DllBase; /* 0x18 */
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName; /* 0x24 */
    UNICODE_STRING BaseDllName; /* 0x28 */
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
         LIST_ENTRY HashLinks;
         struct
         {
              PVOID SectionPointer;
              ULONG CheckSum;
         };
    };
    union
    {
         ULONG TimeDateStamp;
         PVOID LoadedImports;
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

wchar_t ToLowerW(wchar_t ch) {
	if (ch > 0x40 && ch < 0x5B) {
		return ch + 0x20;
	}
	return ch;
}

int StringContains(wchar_t* haystack, wchar_t* needle) {
	if (haystack == NULL || needle == NULL) {
		return 0;
	}

	for (int i = 0; haystack[i] != '\0'; i++) {
		if (ToLowerW(haystack[i]) == ToLowerW(needle[0])) {
			int found = 1;
			for (int j = 1; needle[j] != '\0'; j++) {
				if (ToLowerW(haystack[i + j]) != ToLowerW(needle[j])) {
					found = 0;
				}
			}
			if (found) {
				return 1;
			}
		}
	}
	return 0;
}


PLDR_DATA_TABLE_ENTRY GetLdrDataTableEntry(wchar_t* dllName) {
	//PTIB pTIB = GetTIB();
	//PPEB pPEB = pTIB->pPEB;

    PPEB pPEB;
    __asm__ volatile(
        ".intel_syntax noprefix ;"
        "mov %0, dword ptr fs:[0x30] ;"
        ".att_syntax noprefix ;"
        : "+r"(pPEB) : :
    );

    printf("PEB: %p\n", pPEB);

	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY moduleList = moduleListTail->Flink;

	do {
		unsigned char* modulePtrWithOffset = (unsigned char*)moduleList - (sizeof(LIST_ENTRY));

		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)modulePtrWithOffset;
		//fprintf(stderr, "Entry: %p\n", entry);
        wprintf(L"KTM: %s\n", entry->BaseDllName.Buffer);
		//wprintf(L"%s\n", entry->BaseDllName.buffer);
		/*if (StringContains(entry->BaseDllName.buffer, dllName)) {
			return entry;
		}*/
		moduleList = moduleList->Flink;
	} while (moduleList != moduleListTail);

	return NULL;
}

int main() {

    PLDR_DATA_TABLE_ENTRY ktm;
    ktm = GetLdrDataTableEntry(L"pinvm");
    printf("%p\n", ktm);
	exit(0);
    ktm = GetLdrDataTableEntry(L"bluepill");
    printf("%p\n", ktm);
    return 0;
}