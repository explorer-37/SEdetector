#include "apimonitor.h"

int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	// get WinAPIs
	HMODULE kernel32;
	HMODULE shell32;
	if((kernel32 = GetModuleHandle("kernel32"))) {
		oriIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
	}
	if((shell32 = GetModuleHandle("shell32"))) {
		oriShellAboutW = GetProcAddress(shell32, "ShellAboutW");
	}

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			// set API hook
			ModifyIat("kernel32.dll", newIsDebuggerPresent, oriIsDebuggerPresent);
			ModifyIat("shell32.dll", newShellAboutW, oriShellAboutW);
			//CreateNamedPipe("\\\\.\\pipe\\SEdetector",);
			IsDebuggerPresent(); // for debugging
			break;
		case DLL_PROCESS_DETACH:
			// restore IAT
			ModifyIat("kernel32.dll", oriIsDebuggerPresent, newIsDebuggerPresent);
			ModifyIat("shell32.dll", oriShellAboutW, newShellAboutW);
			break;
		default:
			;
	}

	return 1;
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

void GetCallApi(char *apiname, ...){
	// send API information using named pipe
	char str[512] = {};
	sprintf(str, "%256s called.", apiname); // for debugging
	MessageBox(NULL, str, "debug", MB_SYSTEMMODAL); // for debugging
	return;
}

BOOL WINAPI newIsDebuggerPresent(){
	GetCallApi("IsDebuggerPresent");
	return oriIsDebuggerPresent();
}

INT WINAPI newShellAboutW(HWND hWnd, LPCWSTR szApp, LPCWSTR szOtherStuff, HICON hIcon){
	GetCallApi("ShellAboutW", hWnd, szApp, szOtherStuff, hIcon);
	return oriShellAboutW(hWnd, L"ShellAboutW hooked!", szOtherStuff, hIcon); // for debugging
}
