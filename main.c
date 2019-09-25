////////////////////////////////////////////////////////////////////////////////
///// main.c                                                                  //
////                                                                          //
///   Mws Cup2019 (input team name)                                           //
//    Sandbox Evasion Detector                                               ///
//                                                                          ////
//    Last Modified: 09/25/2019                                            /////
////////////////////////////////////////////////////////////////////////////////


#include "SEdetector.h"

int main(int argc, char *argv[]){
	// initialize
	char *path, *cmd;
		if (argc < 2) {
			fprintf(stderr, "Usage: %s [file]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
		path = argv[1];
		if (argc == 2)
			cmd = NULL;
		else
			cmd = argv[2];

	// create target process and inject DLL into the process
	{
		STARTUPINFOA sInfo = {};
		sInfo.cb = sizeof(sInfo);
		PROCESS_INFOMATION pInfo = {};
		char dllPath[] = "apimonitor.dll";
		void *dllAddress;
		HMODULE kernel32;
		FARPROC loadlibrary;
		HANDLE hLoadLibraryThread;

		if (!CreateProcessA(path, cmd, NULL, NULL, 0x0, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo)) {
			fprintf(stderr, "Cannot create process.\nPath: %s\n", path);
			exit((int)GetLastError());
		}
		if (!(address = VirtualAllocEx(pInfo.hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE))) {
			fprintf(stderr, "Cannot allocate memory on target process.\n");
			exit((int)GetLastError());
		}
		if (!WriteProcessMemory(pInfo.hProcess, address, (void *)dllPath, sizeof(dllPath), NULL)) {
			fprintf(stderr, "Cannot write memory of target process.\n");
			exit((int)GetLastError());
		}

		kernel32 = GetModuleHandle("kernel32");
		loadlibrary = GetProcAddress(kernel32, "LoadLibraryA");
		if (!(hLoadLibraryThread = CreateRemoteThread(pInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlibrary, dllAddress, 0, NULL))) {
			fprintf(stderr, "Cannot create new thread on target process.\n");
			exit(GetLastError());
		}
		WaitForSingleObject(hLoadLibraryThread, INFINITE);

		CloseHandle(hLoadLibraryThread);
		VirtualFreeEx(pInfo.hProcess, dllAddress, sizeof(dllPath), MEM_RELEASE);
	}


	// start monitoring WinAPI (using dll injection)
	// author: NAKAMURA
	
	// detect sandbox evasion
	
	// finalize
	// Kill target process first.
	CloseHandle(sInfo.hStdInput);
	CloseHandle(sInfo.hStdOutput);
	CloseHandle(sInfo.hStdError);
	CloseHandle(pInfo.hThread);
	CloseHandle(pInfo.hProcess);
}
