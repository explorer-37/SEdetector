#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

void EnumModule();
void ModifyIAT(char *dllname, void *newaddr, void *oldaddr);

int WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
	//HMODULE shell32 = GetModuleHandle("shell32");
	//oriShellAboutW = GetProcAddress(shell32, "ShellAboutW");

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			MessageBox(
					NULL, // hWnd
					"This process is hacked!", // lpText
					"Error", // lpCaption
					MB_SYSTEMMODAL // uType
				);
			//ModifyIAT("shell32.dll", oriShellAboutW, newShellAboutW);
			EnumModule();
			break;
		case DLL_PROCESS_DETACH:
			//ModifyIAT("shell32.dll", newShellAboutW, oriShellAboutW);
			break;
		default:
			;
	}

	return 1;
}

void EnumModule(){
	int i = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
	MODULEENTRY32 me32 = {};
	me32.dwSize = sizeof(MODULEENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return;
	if (!Module32First(hSnapshot, &me32))
		return;

	do {
		i++;
		printf("%d: %s\n", i, me32.szModule);
		printf("Base address = 0x%x\n", me32.modBaseAddr);
	} while (Module32Next(hSnapshot,&me32));

	CloseHandle(hSnapshot);
}

void ModifyIAT(char *dllname, void *newaddr, void *oldaddr) {
	HANDLE snapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, // dwFlags
			0 // th32ProcessID; 0 indicates current process id
			);

}
