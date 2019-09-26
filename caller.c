#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(int argc, char *argv[]){
	char file[256];
	char *cmd = (char *)malloc(sizeof(char) * 256);
	STARTUPINFOA sInfo = {};
	// {
	// 	0x44, // cb, 68bytes
	// 	NULL, // lpReserved
	// 	, // lpDesktop
	// 	NULL, // lpTitle
	// 	, // dwX
	// 	, // dwY
	// 	, // dwXSize
	// 	, // dwYSize
	// 	, // dwXCountChars
	// 	, // dwYCountChars
	// 	, // dwFillAttribute
	// 	0x0, // dwFlag
	// 	, // wShowWindow
	// 	0x0, // cbReserved2
	// 	NULL, // lpReserved2
	// 	, // hStdInput
	// 	, // hStdOutput
	// 	, // hStdError
	// };
	sInfo.cb = sizeof(sInfo);
	PROCESS_INFORMATION pInfo = {};
	// {
	// 	HANDLE hProcess,
	// 	HANDLE hThread,
	// 	DWORD dwProcessId,
	// 	DWORD dwThreadId
	// }
	//char *dllPath = "C:\\Users\\nakamura\\Documents\\programs\\mws\\SEdetector\\DisplayMessage.dll";
	char dllPath[] = "DisplayMessage.dll";
	void *dllAddress;

	HMODULE kernel32;
	FARPROC loadlibrary;
	HANDLE hLoadLibraryThread;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	strcpy(file, argv[1]);
	if (argc > 2)
		strcpy(cmd, argv[2]);
	else
		cmd = NULL;

	if (CreateProcessA(
			file, // lpApplicationName
			cmd, // lpCommandLine
			NULL, // lpProcessAttributes
			NULL, // lpThreadAttributes
			0x0, // bInheritHandles
			NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, // dwCreationFlags
			NULL, // lpEnvironment
			NULL, // lpCurrentDirectory
			&sInfo, // lpStartupInfo
			&pInfo // lpProcessInformation
			) == 0) {
		fprintf(stderr, "Cannot create process.\nPath: %s\n", argv[1]);
		fprintf(stderr, "Error code: %d\n", (int)GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Created process.\nPID = %d TID = %d\n", (int)pInfo.dwProcessId, (int)pInfo.dwThreadId);
	if(!(dllAddress = VirtualAllocEx(
			pInfo.hProcess, // hProcess
			NULL, // lpAddress
			sizeof(dllPath), // dwSize
			MEM_COMMIT, // flAllocationType
			PAGE_READWRITE // flProtect
			))) {
		fprintf(stderr, "Cannot allocate memory on target process.\nPID: %d\n", (int)pInfo.dwProcessId);
		exit((int)GetLastError());
	}
	if(!WriteProcessMemory(
			pInfo.hProcess, // hProcess
			dllAddress, // lpBaseAddress
			(void *)dllPath, // lpBuffer
			sizeof(dllPath), // nSize
			NULL // lpNumberOfBytesWritten
			)) {
		fprintf(stderr, "Cannot write memory of target process.\n");
		exit(GetLastError());
	}
	char buf[256] = {};
	ReadProcessMemory(pInfo.hProcess, dllAddress, buf, sizeof(dllPath), NULL);
	printf("%s\n", buf);
	printf("%d\n", (int)sizeof(dllPath));

	if(!(kernel32 = GetModuleHandle("kernel32"))) {
		fprintf(stderr, "Cannot get handle of kernel32\n");
		exit(GetLastError());
	}
	if(!(loadlibrary = GetProcAddress(kernel32, "LoadLibraryA"))) {
		fprintf(stderr, "Cannot get proc address of loadlibrary\n");
		exit(GetLastError());
	}
	printf("Address of LoadLibraryA = 0x%I64x\n", (unsigned long long)loadlibrary);
	if(!(hLoadLibraryThread = CreateRemoteThread(
			pInfo.hProcess, // hProcess
			NULL, // lpThreadAttributes
			0, // dwStackSize
			(LPTHREAD_START_ROUTINE)loadlibrary, // lpStartAddress
			dllAddress, // lpParameter
			0, // dwCreationFlags
			NULL // lpThreadId
			))) {
		fprintf(stderr, "Cannot create new thread on target process.\n");
		exit(GetLastError());
	}
	WaitForSingleObject(hLoadLibraryThread, INFINITE);
	printf("DllMain finished.\n");
	CloseHandle(hLoadLibraryThread);
	VirtualFreeEx(
			pInfo.hProcess, // hProcess
			dllAddress, // lpAddress
			sizeof(dllPath), // dwSize
			MEM_RELEASE // dwFreeType
			);

	if(ResumeThread(pInfo.hThread) == -1)
		printf("Cannot resume thread.\n");
	else
		printf("Resuming thread.\n");

	CloseHandle(sInfo.hStdInput);
	CloseHandle(sInfo.hStdOutput);
	CloseHandle(sInfo.hStdError);
	CloseHandle(pInfo.hThread);
	CloseHandle(pInfo.hProcess);
	return 0;
}
