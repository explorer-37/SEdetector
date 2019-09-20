#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]){
	STARTUPINFOA sInfo = {};
	PROCESS_INFORMATION pInfo = {};
	sInfo.cb = sizeof(sInfo);
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

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (CreateProcessA(
			argv[1], // lpApplicationName
			NULL, // lpCommandLine
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
		exit(EXIT_FAILURE);
	}
	printf("Created process.\nPID = %d\nTID = %d\n", (int)pInfo.dwProcessId, (int)pInfo.dwThreadId);

	if(ResumeThread(pInfo.hThread) == -1)
		printf("Cannot resume thread.\n");
	else
		printf("Resuming thread.\n");

	CloseHandle(pInfo.hThread);
	CloseHandle(pInfo.hProcess);
	return 0;
}
