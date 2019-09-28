#include "apimonitor.h"

int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	//HMODULE kernel32;
	//if((kernel32 = GetModuleHandle("kernel32"))) {
	//	oriapi[IDX_ISDEBUGGERPRESENT] = GetProcAddress(kernel32, "IsDebuggerPresent");
	//}

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			// get WinAPIs
			GetApiEntry();
			// set API hook
			ModifyIat("kernel32.dll", newIsDebuggerPresent, oriapi[IDX_ISDEBUGGERPRESENT].addr);
			ModifyIat("kernel32.dll", newGetFileAttributes, oriapi[IDX_GETFILEATTRIBUTES].addr);
			ModifyIat("Advapi32.dll", newRegOpenKeyEx, oriapi[IDX_REGOPENKEYEX].addr);
			//CreateNamedPipe("\\\\.\\pipe\\SEdetector",);
			IsDebuggerPresent(); // for debugging
			break;
		case DLL_PROCESS_DETACH:
			// restore IAT
			IsDebuggerPresent(); // for debugging
			ModifyIat("kernel32.dll", oriapi[IDX_ISDEBUGGERPRESENT].addr, newIsDebuggerPresent);
			ModifyIat("kernel32.dll", oriapi[IDX_GETFILEATTRIBUTES].addr, newGetFileAttributes);
			ModifyIat("Advapi32.dll", oriapi[IDX_REGOPENKEYEX].addr, newRegOpenKeyEx);
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
		{
			char *name = "IsDebbugerPresent";
			oriapi[IDX_ISDEBUGGERPRESENT].addr = GetProcAddress(kernel32, "IsDebuggerPresent");
			oriapi[IDX_ISDEBUGGERPRESENT].Name = name;
			oriapi[IDX_ISDEBUGGERPRESENT].NumArg = 0;
		}
		{
			char *name = "GetFileAttributes";
			oriapi[IDX_GETFILEATTRIBUTES].addr = GetProcAddress(kernel32, "GetFileAttributes");
			oriapi[IDX_GETFILEATTRIBUTES].Name = name;
			oriapi[IDX_GETFILEATTRIBUTES].NumArg = 1;
			oriapi[IDX_GETFILEATTRIBUTES].Arg = (int *)malloc(sizeof(int));
			oriapi[IDX_GETFILEATTRIBUTES].Arg[0] = TYPE_STRING;
		}
	}
	if((advapi32 = GetModuleHandle("Advapi32"))) {
		{
			char *name = "RegOpenKeyEx";
			oriapi[IDX_REGOPENKEYEX].addr = GetProcAddress(advapi32, "RegOpenKeyEx");
			oriapi[IDX_REGOPENKEYEX].Name = name;
			oriapi[IDX_REGOPENKEYEX].NumArg = 5;
			oriapi[IDX_REGOPENKEYEX].Arg = (int *)malloc(sizeof(int) * 5);
			oriapi[IDX_REGOPENKEYEX].Arg[0] = TYPE_ADDR;
			oriapi[IDX_REGOPENKEYEX].Arg[1] = TYPE_STRING;
			oriapi[IDX_REGOPENKEYEX].Arg[2] = TYPE_INT;
			oriapi[IDX_REGOPENKEYEX].Arg[3] = TYPE_ATTRIBUTE16;
			oriapi[IDX_REGOPENKEYEX].Arg[4] = TYPE_ADDR;
		}
	}

	CloseHandle(kernel32);
	CloseHandle(advapi32);
}

void ModifyIat(char *dllname, void *newaddr, void *oldaddr){
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

void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule){
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
			char str[256];
			sprintf(str, "addr = 0x%I64x", (unsigned long long int)*paddr); // for debugging
			MessageBox(NULL, str, "debug", MB_SYSTEMMODAL); // for debugging
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
	int arg_int; unsigned short arg_uint16; unsigned int arg_uint32; u_int64 arg_uint64; char *arg_str;

	strncpy(str, oriapi[ApiIndex].Name, MAX_STR);

	if (oriapi[ApiIndex].NumArg > 0) {
		va_start(arglist, ApiIndex);
		for (i = 0; i < oriapi[ApiIndex].NumArg; i++) {
			switch (oriapi[ApiIndex].Arg[i]) {
				case TYPE_INT:
					arg_int = (int)va_arg(arglist, int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %d", tmp, arg_int);
				case TYPE_ADDR:
					arg_uint64 = (u_int64)va_arg(arglist, u_int64);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %I64x", tmp, arg_uint64);
				case TYPE_ATTRIBUTE16:
					arg_uint16 = (unsigned short)va_arg(arglist, unsigned int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %x", tmp, arg_uint16);
				case TYPE_ATTRIBUTE32:
					arg_uint32 = (unsigned int)va_arg(arglist, unsigned int);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %x", tmp, arg_uint32);
				case TYPE_ATTRIBUTE64:
					arg_uint64 = (u_int64)va_arg(arglist, u_int64);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %I64x", tmp, arg_uint64);
				case TYPE_STRING:
					arg_str = (char *)va_arg(arglist, char*);
					strncpy(tmp, str, MAX_STR);
					snprintf(str, MAX_STR, "%s, %s", tmp, arg_str);
				default:
					;
			}
		}
		va_end(arglist);
	}
	MessageBox(NULL, str, "debug", MB_SYSTEMMODAL); // for debugging
	return;
}

BOOL WINAPI newIsDebuggerPresent(){
	GetCallApi(IDX_ISDEBUGGERPRESENT);
	return oriapi[IDX_ISDEBUGGERPRESENT].addr();
}

DWORD WINAPI newGetFileAttributes(LPCTSTR lpFileName){
	GetCallApi(IDX_GETFILEATTRIBUTES, lpFileName);
	return oriapi[IDX_GETFILEATTRIBUTES].addr();
}
LONG newRegOpenKeyEx(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult){
	GetCallApi(IDX_REGOPENKEYEX, hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return oriapi[IDX_REGOPENKEYEX].addr();
}
