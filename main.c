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
	APIINFO ApiInfo[MAX_HOOKED_API];
	int num_hooked_api = 0;

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

		if (!CreateProcessA(path, cmd, NULL, NULL, 0x0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo)) {
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

	//printf("started listening\n"); // for debugging
	while (1) {
		char str[MAX_STR];

		ReadFile(hPipe, str, sizeof(str), NULL, &Overlapped);
		while (!HasOverlappedIoCompleted(&Overlapped)) {
			if (WaitForSingleObject(pInfo.hThread, 0) == WAIT_OBJECT_0)
				break;
			SleepEx(1, FALSE);
		}
		if (WaitForSingleObject(pInfo.hThread, 0) == WAIT_OBJECT_0)
			break;
		//fprintf(stderr, "%s\n", str); // for debugging
		if(StrToApiInfo(str, &ApiInfo[num_hooked_api])) {
			printApiInfo(&ApiInfo[num_hooked_api]); fflush(stderr); // for debugging
			num_hooked_api++;
		}
		if (num_hooked_api >= MAX_HOOKED_API)
			break;
	}
	CloseHandle(Overlapped.hEvent);
	CloseHandle(hPipe);

	// finalize
	{
		int i;

		CheckSE(ApiInfo, num_hooked_api); // detect sandbox evasion
		for (i = 0; i < num_hooked_api; i++)
			FreeApiInfo(&ApiInfo[i]);
		CloseHandle(pInfo.hThread);
		CloseHandle(pInfo.hProcess);
	}
}

void printApiInfo(APIINFO *ApiInfo){
	int i;
	int *arg_int;
	unsigned short *arg_attr16;
	unsigned int *arg_attr32;
	unsigned long long *arg_attr64, *arg_addr;
	char *arg_str;
	fprintf(stderr, "%s\n", ApiInfo->Name);
	fprintf(stderr, "type = %d\n", ApiInfo->Index);
	for (i = 0; i < numArgApi[ApiInfo->Index]; i++) {
			switch (GetTypeArgument(ApiInfo->Index, i)) {
				case TYPE_INT:
					arg_int = (int *)ApiInfo->Arg[i];
					fprintf(stderr, "    %d\n", *arg_int);
					break;
				case TYPE_ATTR16:
					arg_attr16 = (unsigned short *)ApiInfo->Arg[i];
					fprintf(stderr, "    0x%x\n", *arg_attr16);
					break;
				case TYPE_ATTR32:
					arg_attr32 = (unsigned int *)ApiInfo->Arg[i];
					fprintf(stderr, "    0x%x\n", *arg_attr32);
					break;
				case TYPE_ATTR64:
					arg_attr64 = (unsigned long long *)ApiInfo->Arg[i];
					fprintf(stderr, "    0x%I64x\n", *arg_attr64);
					break;
				case TYPE_ADDR:
					arg_addr = (unsigned long long *)ApiInfo->Arg[i];
					fprintf(stderr, "    0x%I64x\n", *arg_addr);
					break;
				case TYPE_STR:
					arg_str = (char *)ApiInfo->Arg[i];
					fprintf(stderr, "    %s\n", arg_str);
					break;
			}
	}
}

int NameToApiIndex(char *Name){
	if (lstrcmp(Name, "IsDebuggerPresent") == 0)
		return IDX_ISDEBUGGERPRESENT;
	if (lstrcmp(Name, "GetFileAttributesA") == 0)
		return IDX_GETFILEATTRIBUTESA;
	if (lstrcmp(Name, "RegOpenKeyExA") == 0)
		return IDX_REGOPENKEYEXA;
	if (lstrcmp(Name, "CreateFileA") == 0)
		return IDX_CREATEFILEA;
	// writing
	return IDX_INVALID_API;
}

void ConvertArgument(char *str, APIINFO *ApiInfo, int arg, int type) {
	int *arg_int;
	unsigned short *arg_attr16;
	unsigned int *arg_attr32;
	unsigned long long *arg_attr64;
	unsigned long long *arg_addr;
	char *arg_str;
	switch (type) {
		case TYPE_INT:
			arg_int = (int *)malloc(sizeof(int *));
			*arg_int = atoi(str);
			ApiInfo->Arg[arg] = arg_int;
			break;
		case TYPE_ATTR16:
			arg_attr16 = (unsigned short *)malloc(sizeof(unsigned short *));
			*arg_attr16 = strtoul(str, NULL, 0);
			ApiInfo->Arg[arg] = arg_attr16;
			break;
		case TYPE_ATTR32:
			arg_attr32 = (unsigned int *)malloc(sizeof(unsigned int *));
			*arg_attr32 = strtoul(str, NULL, 0);
			ApiInfo->Arg[arg] = arg_attr32;
			break;
		case TYPE_ATTR64:
			arg_attr64 = (unsigned long long *)malloc(sizeof(unsigned long long *));
			*arg_attr64 = strtoull(str, NULL, 0);
			ApiInfo->Arg[arg] = arg_attr64;
			break;
		case TYPE_ADDR:
			arg_addr = (unsigned long long *)malloc(sizeof(unsigned long long *));
			*arg_addr = strtoull(str, NULL, 0);
			ApiInfo->Arg[arg] = arg_addr;
			break;
		case TYPE_STR:
			arg_str = (char *)malloc(sizeof(char) * MAX_BUF);
			lstrcpyn(arg_str, str, MAX_BUF);
			ApiInfo->Arg[arg] = arg_str;
			break;
		default:
			;
	}
}

int StrToApiInfo(char *str, APIINFO *ApiInfo){
	int i;
	int type;
	char *buf[MAX_ARG + 1];

	buf[0] = strtok(str, "\n");
	for (i = 0; i < MAX_ARG; i++) {
		if (!(buf[i+1] = strtok(NULL, "\n")))
			break;
	}

	ApiInfo->Name = (char *)malloc(sizeof(char) * MAX_BUF);
	lstrcpyn(ApiInfo->Name, buf[0], MAX_BUF);

	ApiInfo->Index = NameToApiIndex(ApiInfo->Name);
	if (ApiInfo->Index == IDX_INVALID_API)
		return 0;

	for (i = 0; i < GetNumArgument(ApiInfo->Index); i++) {
		if (buf[i+1] == NULL)
			return 0;
		type = GetTypeArgument(ApiInfo->Index, i);
		ConvertArgument(buf[i+1], ApiInfo, i, type);
	}

	return 1;
}

void FreeApiInfo(APIINFO *ApiInfo){
	int i;
	free(ApiInfo->Name);
	for (i = 0; i < GetNumArgument(ApiInfo->Index); i++) {
		free(ApiInfo->Arg[i]);
	}
}
