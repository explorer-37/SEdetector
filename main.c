/*!
 * main.c
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "main.h"

int main(int argc, char *argv[]){
	// initialize
	char *path, *cmd;
	PROCESS_INFORMATION pInfo = {};
	HANDLE hPipe;
	OVERLAPPED Overlapped = {};
	Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	path = argv[1];
	if (argc == 2)
		cmd = NULL;
	else
		cmd = argv[2];

	// create named pipe for recieving informations
	{
		hPipe = CreateNamedPipeA("\\\\.\\pipe\\SEdetector", PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, PIPE_BUFFER, PIPE_BUFFER, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "0x%x\n", (int)GetLastError());
			exit(EXIT_FAILURE);
		}
		ConnectNamedPipe(hPipe, &Overlapped);
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
			exit(GetLastError());
		}
		CloseHandle(sInfo.hStdInput);
		CloseHandle(sInfo.hStdOutput);
		CloseHandle(sInfo.hStdError);
		if (!(dllAddress = VirtualAllocEx(pInfo.hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE))) {
			fprintf(stderr, "Cannot allocate memory on target process.\n");
			exit(GetLastError());
		}
		if (!WriteProcessMemory(pInfo.hProcess, dllAddress, (void *)dllPath, sizeof(dllPath), NULL)) {
			fprintf(stderr, "Cannot write memory of target process.\n");
			exit(GetLastError());
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
	ResumeThread(pInfo.hThread);

	while(!HasOverlappedIoCompleted(&Overlapped)) {
		SleepEx(1, FALSE);
	}

	printf("started listening\n"); // for debugging
	while (1) {
		char str[MAX_STR];
		APIINFO ApiInfo = {};
		ReadFile(hPipe, str, sizeof(str), NULL, &Overlapped);
		while (!HasOverlappedIoCompleted(&Overlapped)) {
			if (WaitForSingleObject(pInfo.hThread, 0) == WAIT_OBJECT_0)
				break;
			SleepEx(1, FALSE);
		}
		if (WaitForSingleObject(pInfo.hThread, 0) == WAIT_OBJECT_0)
			break;
		printf("%s\n", str); // for debugging
		StrToApiInfo(str, &ApiInfo);
		CheckSE(&ApiInfo);
		ClearApiInfo(&ApiInfo);
	}
	CloseHandle(Overlapped.hEvent);
	CloseHandle(hPipe);

	// detect sandbox evasion
	
	// finalize
	CloseHandle(pInfo.hThread);
	CloseHandle(pInfo.hProcess);
}

int strnsep(char *str, char **buf, const char sep, int num_sep){
	int i;
	for (i = 0; i < num_sep; i++) {
		if (*str == '\0') {
			*buf[i] = '\0';
			break;
		}
		if (*str == sep) {
			*buf[i] = '\0';
			str++;
			continue;
		}
		*buf[i]++ = *str++;
	}
	if (i == num_sep)
		return num_sep;
	return i + 1;
}

int NameToApiIndex(char *Name){
	if (strcmp(Name, "IsDebuggerPresent") == 0)
		return IDX_ISDEBUGGERPRESENT;
	// writing
}

int GetTypeArgument(int index, int arg){
	// writing
}

void ConvertArgument(char *str, APIINFO *ApiInfo, int arg, int type) {
	switch (type) {
		case TYPE_INT:
			ApiInfo->u[arg].arg_int = (int)malloc(sizeof(int));
			ApiInfo->u[arg].arg_int = atoi(str);
			break;
		case TYPE_ATTR16:
			ApiInfo->u[arg].arg_attr16 = (unsigned short int)malloc(sizeof(unsigned short int));
			ApiInfo->u[arg].arg_attr16 = strtol(str, NULL, 0);
			// writing
			break;
		case TYPE_ATTR32:
			ApiInfo->u[arg].arg_attr32 = (unsigned int)malloc(sizeof(unsigned int));
			ApiInfo->u[arg].arg_attr32 = strtol(str, NULL, 0);
			// writing
			break;
		case TYPE_ATTR64:
			ApiInfo->u[arg].arg_attr64 = (unsigned long long)malloc(sizeof(unsigned long long));
			ApiInfo->u[arg].arg_attr64 = strtol(str, NULL, 0);
			// writing
			break;
		case TYPE_ADDR:
			ApiInfo->u[arg].arg_addr = (unsigned long long)malloc(sizeof(unsigned long long));
			ApiInfo->u[arg].arg_addr = strtol(str, NULL, 0);
			// writing
			break;
		case TYPE_STR:
			ApiInfo->u[arg].arg_str = (char *)malloc(sizeof(char *));
			ApiInfo->u[arg].arg_str = str;
			break;
	}
}

void StrToApiInfo(char *str, APIINFO *ApiInfo){
	int i;
	int apiindex, type;
	char *buf[MAX_ARG + 1];
	for (i = 0; i < MAX_ARG + 1; i++) {
		buf[i] = (char *)malloc(sizeof(char) * MAX_BUF);
	}
	ApiInfo->Num_arg = strnsep(str, buf, ',', MAX_ARG + 1) - 1;
	strncpy(ApiInfo->Name,buf[0],MAX_ARG+1);
	apiindex = NameToApiIndex(ApiInfo->Name);
	for (i = 0; i < ApiInfo->Num_arg; i++) {
		type = GetTypeArgument(apiindex, i);
		ConvertArgument(buf[i+1], ApiInfo, apiindex, type);
		if (type != TYPE_STR)
			free(buf[i+1]);
	}
}

void ClearApiInfo(APIINFO *ApiInfo){
	// writing
}
