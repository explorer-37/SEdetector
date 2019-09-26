#include <windows.h>

void ModifyIat(char *dllname, void *newaddr, void *oldaddr);
void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule);

BOOL newIsDebuggerPresent();
FARPROC oriIsDebuggerPresent;

int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	// set API hook
	// get WinAPIs
	if((kernel32 = GetModuleHandle("kernel32"))) {
		oriIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
	}

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			ModifyIat("kernel32.dll", ori, new);
			CreateNamedPipe("\\\\.\\pipe\\SEdetector",);
			break;
		case DLL_PROCESS_DETACH:
			ModifyIat("kernel32.dll", new, ori);
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
		modifyIatOne(dllname, newgaddr, oldaddr, me.hModule);
		bModuleResult = Module32Next(hModuleSnap, &me);
	}

	CloseHandle(hModuleSnap);
}

void GetCalledApi(char *apiname, ...){
	// send API information using named pipe
	return;
}

BOOL newIsDebuggerPresent(){
	GetCalledApi("IsDebuggerPresent");
	return oriIsDebuggerPresent();
}
