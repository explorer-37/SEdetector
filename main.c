/*!
 * main.c
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "SEdetector.h"

int main(int argc, char *argv[]){
	// initialize
	char *path, *cmd;
	PROCESS_INFORMATION pInfo = {};

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	path = argv[1];
	if (argc == 2)
		cmd = NULL;
	else
		cmd = argv[2];

	// create named pipe for recieving information
	{
		//HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\SEdetector", PIPE_ACCESS_INBOUND, ) // writing
	}

	// create target process and inject DLL into the process
	{
		STARTUPINFOA sInfo = {};
		sInfo.cb = sizeof(sInfo);
		char dllPath[] = DLLPATH;
		void *dllAddress;
		HMODULE kernel32;
		FARPROC loadlibrary;
		HANDLE hLoadLibraryThread;

		if (!CreateProcessA(path, cmd, NULL, NULL, 0x0, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo)) {
			fprintf(stderr, "Cannot create process.\nPath: %s\n", path);
			exit((int)GetLastError());
		}
		CloseHandle(sInfo.hStdInput);
		CloseHandle(sInfo.hStdOutput);
		CloseHandle(sInfo.hStdError);
		if (!(dllAddress = VirtualAllocEx(pInfo.hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE))) {
			fprintf(stderr, "Cannot allocate memory on target process.\n");
			exit((int)GetLastError());
		}
		if (!WriteProcessMemory(pInfo.hProcess, dllAddress, (void *)dllPath, sizeof(dllPath), NULL)) {
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
	//while (1) {
	//	char buf[256];
	//	if(!ReadFile(hPipe, buf, sizeof(buf), NULL, NULL))
	//		break;
	//}

	ResumeThread(pInfo.hThread);
	
	// detect sandbox evasion
	
	// finalize
	// Kill target process first.
	CloseHandle(pInfo.hThread);
	CloseHandle(pInfo.hProcess);
}
