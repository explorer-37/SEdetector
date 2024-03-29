/*!
 * apimonitor.h
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define MAX_HOOKED_API 256

#define MAX_STR 65536

#define IDX_ISDEBUGGERPRESENT 0
#define IDX_GETFILEATTRIBUTESA 1
#define IDX_REGOPENKEYEXA 2
#define IDX_CREATEFILEA 3

#define TYPE_INT 0
#define TYPE_ADDR 1
#define TYPE_ATTRIBUTE16 2
#define TYPE_ATTRIBUTE32 3
#define TYPE_ATTRIBUTE64 4
#define TYPE_STRING 5

typedef struct _APIINFO {
	FARPROC oriaddr;
	void *newaddr;
	const char *Dll;
	const char *Name;
	int NumArg;
	int *Arg;
} APIINFO;

void GetApiEntry();

void ModifyIat(const char *dllname, void *newaddr, void *oldaddr);
PIMAGE_IMPORT_DESCRIPTOR GetImportEntry(PVOID Base, PULONG Size);
void ModifyIatOne(const char *dllname, void *newaddr, void *oldaddr, HMODULE hModule);

void GetCallApi(int ApiIndex, ...);


// proclaim of hook api
BOOL WINAPI newIsDebuggerPresent();
DWORD WINAPI newGetFileAttributesA(LPCTSTR lpFileName);
LONG WINAPI newRegOpenKeyExA(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
HANDLE WINAPI newCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

APIINFO ApiInfo[MAX_HOOKED_API] = {};

HANDLE hPipe;
OVERLAPPED Overlapped = {};
