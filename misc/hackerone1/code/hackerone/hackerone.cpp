#include "stdafx.h"
 
#include <iostream> 
#include <fstream>
#include <Windows.h>
#include <sstream>
#include "psapi.h"
#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")


void TlsTest() {

	for (int i = 0; i < 32; i++) {
		cout << TlsGetValue(i) << endl;
	}

}

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_End() X64_End_with_CS(0x23)

void FarRet() {

	X64_Start();
	X64_End();

	cout << "-- Test passed" << endl;

}


void MaxHandle() {
	HANDLE hProcPseudo = GetCurrentProcess();
	LPHANDLE *list = (LPHANDLE*)malloc(sizeof(LPHANDLE) * 17000000);
	memset(list, 0, sizeof(list));
	//Then call either:
	HANDLE lpRealHandle = CreateEvent(NULL, false, false, NULL);
	int i = 0;

	for (i = 0; i < 17000000; i++) {
		bool ret = DuplicateHandle(hProcPseudo, lpRealHandle, hProcPseudo, list[i], DUPLICATE_SAME_ACCESS, 0, 0);
		if (ret==0) break;
	}
	cout << "-- Max Handle: " << i << "   ---  Should be like 16.7M" << endl;

}

void RamUsed() {

	MEMORYSTATUSEX memInfo;
	PROCESS_MEMORY_COUNTERS_EX pmc;
	GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

	cout << "-- Usage of Ram is: " << pmc.WorkingSetSize << endl;
}

void EbxTest() {

	char a[] = "aaaa";
	char b[] = "bbbb";
	DWORD c;

	__asm {
		mov eax, dword ptr [b]
		mov dword ptr [ebx+24h], eax

		mov eax, dword ptr [ebx]
		mov c, eax
	}

	cout << "-- value should be 626262: " << ((void*)c) << endl;

}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
	return std::find(begin, end, option) != end;
}

int main(int argc, char * argv[]) {
	
	if (cmdOptionExists(argv, argv + argc, "-x64"))
	{
		cout << "Far jmp test" << endl;
		FarRet();
	}

	cout << "Test if one tls slot is full" << endl;
	TlsTest();

	cout << "Max handle test" << endl;
	MaxHandle();

	cout << "Max Ram usage test" << endl;
	RamUsed();

	cout << "Max Ram usage test" << endl;
	EbxTest();

}

/*

int main() {

	ifstream inFile;
	size_t size = 0; // here

	inFile.open("C:\\Windows\\system32\\ntdll.dll", ios::in | ios::binary | ios::ate);
	unsigned char* oData = 0;

	inFile.seekg(0, ios::end); // set the pointer to the end
	size = inFile.tellg(); // get the length of the file
	inFile.seekg(0, ios::beg); // set the pointer to the beginning

	oData = new unsigned char[size + 1]; //  for the '\0'
	inFile.read((char*)oData, size);
	oData[size] = '\0'; // set '\0' 

	HINSTANCE hGetProcIDDLL = GetModuleHandle(L"ntdll.dll");

	__asm {
		mov ebx, dword ptr[hGetProcIDDLL]
	}

	for (int i = 0; i < size; i++) {
		unsigned char byte1;
		__asm {
			mov cl, byte ptr[ebx]
			mov byte1, cl
			inc ebx
		}
		printf("%.2x\n", byte1);
		//printf("%.2x - %.2x\n", byte1, oData[i]);
		//if (byte1 != oData[i])
			//printf("%.2x - %.2x\n", byte1, oData[i]);
	}

}

/*

#define FUNC_NAME "KiUserExceptionDispatcher"

typedef int(__stdcall *f_KiUserExceptionDispatcher)(PEXCEPTION_RECORD, CONTEXT*);

int main() {

	HINSTANCE hGetProcIDDLL = LoadLibrary(L"ntdll.dll");

	f_KiUserExceptionDispatcher funci = (f_KiUserExceptionDispatcher)GetProcAddress(hGetProcIDDLL, FUNC_NAME);

	__asm {
		mov ebx, dword ptr[funci]
	}

	for (int i = 0; i < 8; i++) {
		unsigned char byte1;
		__asm {
			mov cl, byte ptr[ebx]
			mov byte1, cl
			inc ebx
		}
		printf("\\x%.2x ", byte1);
	}

	system("pause");

}

*/

/*
int main(int argc, char **argv)
{
	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return 1;                  // Program has failed.
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);


	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator *pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices *pSvc = NULL;

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;                // Program has failed.
	}

	cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// For example, get the name of the operating system
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the Name property
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		wcout << " OS Name : " << vtProp.bstrVal << endl;
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	// Cleanup
	// ========

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return 0;   // Program successfully completed.

}

 */

