#include <windows.h>
#include <stdio.h>
#include <string.h>
//#include <apiset.h>

typedef struct _API_SET_VALUE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	_Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG NameLength;
	ULONG ValueOffset;
	_Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

_Struct_size_bytes_(FIELD_OFFSET(API_SET_VALUE_ARRAY, Array) + (sizeof(API_SET_VALUE_ENTRY)* Count))
typedef struct _API_SET_VALUE_ARRAY {
	ULONG Flags;
	ULONG Count;
	_Field_size_full_(Count) API_SET_VALUE_ENTRY Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY, *PAPI_SET_VALUE_ARRAY;

typedef struct _API_SET_NAMESPACE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	_Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG NameLength;
	ULONG AliasOffset;
	_Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG AliasLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

_Struct_size_bytes_(Size)
typedef struct _API_SET_NAMESPACE_ARRAY {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	_Field_size_full_(Count) API_SET_NAMESPACE_ENTRY Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY, *PAPI_SET_NAMESPACE_ARRAY;

typedef const API_SET_VALUE_ENTRY *PCAPI_SET_VALUE_ENTRY;
typedef const API_SET_VALUE_ARRAY *PCAPI_SET_VALUE_ARRAY;
typedef const API_SET_NAMESPACE_ENTRY *PCAPI_SET_NAMESPACE_ENTRY;
typedef const API_SET_NAMESPACE_ARRAY *PCAPI_SET_NAMESPACE_ARRAY;

typedef struct _API_SET_VALUE_ENTRY_V2 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
	ULONG Count;
	API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
	ULONG Version;
	ULONG Count;
	_Field_size_full_(Count) API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

typedef const API_SET_VALUE_ENTRY_V2 *PCAPI_SET_VALUE_ENTRY_V2;
typedef const API_SET_VALUE_ARRAY_V2 *PCAPI_SET_VALUE_ARRAY_V2;
typedef const API_SET_NAMESPACE_ENTRY *PCAPI_SET_NAMESPACE_ENTRY_V2;
typedef const API_SET_NAMESPACE_ARRAY *PCAPI_SET_NAMESPACE_ARRAY_V2;

template<typename T1, typename T2> void ShowApiSetMapContent(ULONG_PTR ApiSetMapBase);


int __cdecl wmain(int argc, wchar_t **argv)
{
	ULONG_PTR ApiSetMapBase;

	DWORD_PTR pPeb;
#ifdef _WIN64
#define PEB_API_SET_MAP_OFFSET 0x0068
	pPeb = (DWORD_PTR)__readgsqword(12 * sizeof(DWORD_PTR)); //PEB Address
#else
#define PEB_API_SET_MAP_OFFSET 0x0038
	pPeb = (DWORD_PTR)__readfsdword(12 * sizeof(DWORD_PTR)); //PEB Address
#endif

	ApiSetMapBase = *(ULONG_PTR *)(pPeb + PEB_API_SET_MAP_OFFSET);

	API_SET_NAMESPACE_ARRAY_V2 * pNamespaceArray = (API_SET_NAMESPACE_ARRAY_V2 *)ApiSetMapBase;
	
	printf("[*] Base %p, Version %d, total entries in ApiSetMap: %d\n", pNamespaceArray, pNamespaceArray->Version, pNamespaceArray->Count);

	if (pNamespaceArray->Version >= 3)
	{
		ShowApiSetMapContent<API_SET_NAMESPACE_ARRAY, API_SET_VALUE_ARRAY>(ApiSetMapBase);
	}
	else
	{
		ShowApiSetMapContent<API_SET_NAMESPACE_ARRAY_V2, API_SET_VALUE_ARRAY_V2>(ApiSetMapBase);
	}
	
	getchar();
	return 0;
}

template<typename T1, typename T2> void ShowApiSetMapContent(ULONG_PTR ApiSetMapBase)
{
	WCHAR wsDllName[300];
	T1 * pNamespaceArray;
	T2 * pValueArray;

	pNamespaceArray = (T1 *)ApiSetMapBase;

	for (ULONG j = 0; j < pNamespaceArray->Count; j++)
	{
		ZeroMemory(wsDllName, sizeof(wsDllName));
		memcpy(wsDllName, (PVOID)(ApiSetMapBase + pNamespaceArray->Array[j].NameOffset), pNamespaceArray->Array[j].NameLength);
		wprintf(L"%d - %s\n", j, wsDllName);

		pValueArray = (T2 *)(ApiSetMapBase + pNamespaceArray->Array[j].DataOffset);

		if (pValueArray->Count > 2)
		{
			wprintf(L"This is a new Count %d!\n", pValueArray->Count);
			break;
		}

		for (ULONG i = 0; i < pValueArray->Count; i++)
		{
			if (pValueArray->Array[i].NameLength)
			{
				ZeroMemory(wsDllName, sizeof(wsDllName));
				memcpy(wsDllName, (PVOID)(ApiSetMapBase + pValueArray->Array[i].NameOffset), pValueArray->Array[i].NameLength);
				wprintf(L"\t%d Name\t%s -> ", i, wsDllName);
			}
			else
			{
				if (pValueArray->Array[i].ValueLength) wprintf(L"\t%d ", i);
			}

			if (pValueArray->Array[i].ValueLength)
			{
				ZeroMemory(wsDllName, sizeof(wsDllName));
				memcpy(wsDllName, (PVOID)(ApiSetMapBase + pValueArray->Array[i].ValueOffset), pValueArray->Array[i].ValueLength);
				wprintf(L"Value\t%s\n", wsDllName);
			}
		}

	}
}