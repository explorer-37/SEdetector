#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
//#pragma comment(lib, "Dbghelp") // not working at gcc compile

void ModifyIat(char *dllname, void *newaddr, void *oldaddr);
void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule);

void GetCallApi(char *apiname, ...);

BOOL newIsDebuggerPresent();
FARPROC oriIsDebuggerPresent;
INT newShellAboutW();
FARPROC oriShellAboutW;

int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	// set API hook
	// get WinAPIs
	HMODULE kernel32;
	HMODULE shell32;
	if((kernel32 = GetModuleHandle("kernel32"))) {
		oriIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
	}
	if((shell32 = GetModuleHandle("shell32"))) {
		oriIsDebuggerPresent = GetProcAddress(shell32, "IsDebuggerPresent");
	}

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			ModifyIat("kernel32.dll", oriIsDebuggerPresent, newIsDebuggerPresent);
			ModifyIat("shell32.dll", oriShellAboutW, newShellAboutW);
			//CreateNamedPipe("\\\\.\\pipe\\SEdetector",);
			break;
		case DLL_PROCESS_DETACH:
			ModifyIat("kernel32.dll", newIsDebuggerPresent, oriIsDebuggerPresent);
			ModifyIat("shell32.dll", newShellAboutW, oriShellAboutW);
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

void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule){
	ULONG size;
	PIMAGE_IMPORT_DESCRIPTOR pImgDesc = ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
	if (!pImgDesc)
		return;

	while (pImgDesc->Name) {
		char *name = (char *)hModule + pImgDesc->Name;
		if (lstrcmpi(name, dllname) == 0) {
			break;
		}
		pImgDesc++;
	}
	if (!(pImgDesc->Name))
		return ;

	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((char *)hModule + pImgDesc->FirstThunk);
	while (pThunk->u1.Function) {
		PROC *paddr = (PROC *)&pThunk->u1.Function;
		if (*paddr == oldaddr) {
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
	return;
}

BOOL WINAPI newIsDebuggerPresent(){
	GetCallApi("IsDebuggerPresent");
	return oriIsDebuggerPresent();
}

INT WINAPI newShellAboutW(HWND hWnd, LPCWSTR szApp, LPCWSTR szOtherStuff, HICON hIcon){
	//GetCallApi("ShellAboutW", hWnd, szApp, szOtherStuff, hIcon);
	return oriShellAboutW(hWnd, L"ShellAboutW hooked!", szOtherStuff, hIcon);
}
