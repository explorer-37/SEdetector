/*!
 * apimonitor.c
 * SEdetector Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "apimonitor.h"

int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	int i;

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			// get WinAPIs
			GetApiEntry();
			// set API hook
			for (i = 0; i < MAX_HOOKED_API; i++) {
				if (ApiInfo[i].oriaddr)
					ModifyIat(ApiInfo[i].Dll, ApiInfo[i].newaddr, ApiInfo[i].oriaddr);
			}
			//ModifyIat("kernel32.dll", newIsDebuggerPresent, ApiInfo[IDX_ISDEBUGGERPRESENT].addr);
			// connect to named pipe
			hPipe = ApiInfo[IDX_CREATEFILEA].oriaddr("\\\\.\\pipe\\SEdetector", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
			if (hPipe == INVALID_HANDLE_VALUE) {
				//MessageBox(NULL, "Cannnot connect to pipe", "debug", MB_OK); // for debugging
				exit(EXIT_FAILURE);
			}
			Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
			break;
		case DLL_PROCESS_DETACH:
			CloseHandle(hPipe);
			// restore IAT
			for (i = 0; i < MAX_HOOKED_API; i++) {
				if (ApiInfo[i].oriaddr)
					ModifyIat(ApiInfo[i].Dll, ApiInfo[i].oriaddr, ApiInfo[i].newaddr);
			}
			//ModifyIat("kernel32.dll", ApiInfo[IDX_ISDEBUGGERPRESENT].oriaddr, newIsDebuggerPresent);
			break;
		default:
			;
	}

	return 1;
}

void GetApiEntry(){
	HMODULE kernel32;
	HMODULE advapi32;
	if((kernel32 = GetModuleHandle("kernel32"))) {
		const char *dll = "kernel32.dll";
		{
			const char *name = "IsDebuggerPresent";
			ApiInfo[IDX_ISDEBUGGERPRESENT].oriaddr = GetProcAddress(kernel32, "IsDebuggerPresent");
			ApiInfo[IDX_ISDEBUGGERPRESENT].newaddr = (void *)newIsDebuggerPresent;
			ApiInfo[IDX_ISDEBUGGERPRESENT].Name = name;
			ApiInfo[IDX_ISDEBUGGERPRESENT].Dll = dll;
			ApiInfo[IDX_ISDEBUGGERPRESENT].NumArg = 0;
		}
		{
			const char *name = "GetFileAttributesA";
			ApiInfo[IDX_GETFILEATTRIBUTESA].oriaddr = GetProcAddress(kernel32, "GetFileAttributesA");
			ApiInfo[IDX_GETFILEATTRIBUTESA].newaddr = (void *)newGetFileAttributesA;
			ApiInfo[IDX_GETFILEATTRIBUTESA].Name = name;
			ApiInfo[IDX_GETFILEATTRIBUTESA].Dll = dll;
			ApiInfo[IDX_GETFILEATTRIBUTESA].NumArg = 1;
			ApiInfo[IDX_GETFILEATTRIBUTESA].Arg = (int *)malloc(sizeof(int));
			ApiInfo[IDX_GETFILEATTRIBUTESA].Arg[0] = TYPE_STRING;
		}
		{
			const char *name = "CreateFileA";
			ApiInfo[IDX_CREATEFILEA].oriaddr = GetProcAddress(kernel32, "CreateFileA");
			ApiInfo[IDX_CREATEFILEA].newaddr = (void *)newCreateFileA;
			ApiInfo[IDX_CREATEFILEA].Name = name;
			ApiInfo[IDX_CREATEFILEA].Dll = dll;
			ApiInfo[IDX_CREATEFILEA].NumArg = 7;
			ApiInfo[IDX_CREATEFILEA].Arg = (int *)malloc(sizeof(int) * 7);
			ApiInfo[IDX_CREATEFILEA].Arg[0] = TYPE_STRING;
			ApiInfo[IDX_CREATEFILEA].Arg[1] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_CREATEFILEA].Arg[2] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_CREATEFILEA].Arg[3] = TYPE_ADDR;
			ApiInfo[IDX_CREATEFILEA].Arg[4] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_CREATEFILEA].Arg[5] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_CREATEFILEA].Arg[6] = TYPE_ADDR;
		}
	}
	if((advapi32 = GetModuleHandle("Advapi32"))) {
		const char *dll = "Advapi32.dll";
		{
			const char *name = "RegOpenKeyExA";
			ApiInfo[IDX_REGOPENKEYEXA].oriaddr = GetProcAddress(advapi32, "RegOpenKeyExA");
			ApiInfo[IDX_REGOPENKEYEXA].newaddr = (void *)newRegOpenKeyExA;
			ApiInfo[IDX_REGOPENKEYEXA].Name = name;
			ApiInfo[IDX_REGOPENKEYEXA].Dll = dll;
			ApiInfo[IDX_REGOPENKEYEXA].NumArg = 5;
			ApiInfo[IDX_REGOPENKEYEXA].Arg = (int *)malloc(sizeof(int) * 5);
			ApiInfo[IDX_REGOPENKEYEXA].Arg[0] = TYPE_ADDR;
			ApiInfo[IDX_REGOPENKEYEXA].Arg[1] = TYPE_STRING;
			ApiInfo[IDX_REGOPENKEYEXA].Arg[2] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_REGOPENKEYEXA].Arg[3] = TYPE_ATTRIBUTE32;
			ApiInfo[IDX_REGOPENKEYEXA].Arg[4] = TYPE_ADDR;
		}
	}

	CloseHandle(kernel32);
	CloseHandle(advapi32);
}

void ModifyIat(const char *dllname, void *newaddr, void *oldaddr){
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	MODULEENTRY32 me;
	me.dwSize = sizeof(me);

	BOOL bModuleResult = Module32First(hModuleSnap, &me);
	while (bModuleResult) {
		ModifyIatOne(dllname, newaddr, oldaddr, me.hModule);
		bModuleResult = Module32Next(hModuleSnap, &me);
	}

	CloseHandle(hModuleSnap);
}

// Get entry of image import descriptor from memory image
PIMAGE_IMPORT_DESCRIPTOR GetImportEntry(PVOID Base, PULONG Size){
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Base;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(Base + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE *)pNtHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionalHeader->DataDirectory);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Base + pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	Size = (PULONG)(Base + pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	return pImportDescriptor;
}

void ModifyIatOne(const char *dllname, void *newaddr, void *oldaddr, HMODULE hModule){
	ULONG size;
	//PIMAGE_IMPORT_DESCRIPTOR pImpDesc = ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
	PIMAGE_IMPORT_DESCRIPTOR pImpDesc = GetImportEntry(hModule, &size);
	if (!pImpDesc)
		return;

	while (pImpDesc->Name) {
		char *name = (char *)hModule + pImpDesc->Name;
		if (lstrcmpi(name, dllname) == 0) {
			break;
		}
		pImpDesc++;
	}
	if (!(pImpDesc->Name))
		return ;

	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((char *)hModule + pImpDesc->FirstThunk);
	while (pThunk->u1.Function) {
		PROC *paddr = (PROC *)&pThunk->u1.Function;
		if (*paddr == oldaddr) {
			//char str[256]; // for debugging
			//sprintf(str, "addr = 0x%I64x", (unsigned long long int)*paddr); // for debugging
			//MessageBox(NULL, str, "debug", MB_SYSTEMMODAL); // for debugging
			DWORD flOldProtect;
			VirtualProtect(paddr, sizeof(paddr), PAGE_EXECUTE_READWRITE, &flOldProtect);
			*paddr = newaddr;
			VirtualProtect(paddr, sizeof(paddr), flOldProtect, &flOldProtect);
		}
		pThunk++;
	}
}

void GetCallApi(int ApiIndex, ...){
	// send API information using named pipe
	int i;
	char str[MAX_STR], tmp[MAX_STR];
	va_list arglist;
	int arg_int; unsigned long arg_addr; unsigned short arg_uint16; unsigned int arg_uint32; unsigned long long arg_uint64; char *arg_str;

	strncpy(str, ApiInfo[ApiIndex].Name, MAX_STR);

	if (ApiInfo[ApiIndex].NumArg > 0) {
		va_start(arglist, ApiIndex);
		for (i = 0; i < ApiInfo[ApiIndex].NumArg; i++) {
			switch (ApiInfo[ApiIndex].Arg[i]) {
				case TYPE_INT:
					arg_int = va_arg(arglist, int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n%d", tmp, arg_int);
					break;
				case TYPE_ADDR:
					arg_addr = va_arg(arglist, unsigned long);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n0x%lx", tmp, arg_addr);
					break;
				case TYPE_ATTRIBUTE16:
					arg_uint16 = va_arg(arglist, unsigned int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n0x%x", tmp, arg_uint16);
					break;
				case TYPE_ATTRIBUTE32:
					arg_uint32 = va_arg(arglist, unsigned int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n0x%x", tmp, arg_uint32);
					break;
				case TYPE_ATTRIBUTE64:
					arg_uint64 = va_arg(arglist, unsigned long long);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n0x%I64x", tmp, arg_uint64);
					break;
				case TYPE_STRING:
					arg_str = va_arg(arglist, char*);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s\n%s", tmp, arg_str);
					break;
				default:
					;
			}
		}
		va_end(arglist);
	}

	WriteFile(hPipe, str, sizeof(str), NULL, &Overlapped);
	while (!HasOverlappedIoCompleted(&Overlapped))
		SleepEx(1, FALSE);

	//MessageBox(NULL, str, "debug", MB_SYSTEMMODAL); // for debugging
	return;
}

BOOL WINAPI newIsDebuggerPresent(){
	GetCallApi(IDX_ISDEBUGGERPRESENT);
	return ApiInfo[IDX_ISDEBUGGERPRESENT].oriaddr();
}

DWORD WINAPI newGetFileAttributesA(LPCTSTR lpFileName){
	GetCallApi(IDX_GETFILEATTRIBUTESA, lpFileName);
	return ApiInfo[IDX_GETFILEATTRIBUTESA].oriaddr(lpFileName);
}

LONG WINAPI newRegOpenKeyExA(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult){
	GetCallApi(IDX_REGOPENKEYEXA, hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return ApiInfo[IDX_REGOPENKEYEXA].oriaddr(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

HANDLE WINAPI newCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	GetCallApi(IDX_CREATEFILEA, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	return ApiInfo[IDX_CREATEFILEA].oriaddr(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
