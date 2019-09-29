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

#define MAX_ORIAPI 256

#define MAX_STR 65536

#define IDX_ISDEBUGGERPRESENT 0
#define IDX_GETFILEATTRIBUTESA 1
#define IDX_REGOPENKEYEXA 2

#define TYPE_INT 0
#define TYPE_ADDR 1
#define TYPE_ATTRIBUTE16 2
#define TYPE_ATTRIBUTE32 3
#define TYPE_ATTRIBUTE64 4
#define TYPE_STRING 5

typedef struct _APIINFO {
	FARPROC addr;
	const char *Name;
	int NumArg;
	int *Arg;
} APIINFO;

void GetApiEntry();

void ModifyIat(char *dllname, void *newaddr, void *oldaddr);
PIMAGE_IMPORT_DESCRIPTOR GetImportEntry(PVOID Base, PULONG Size);
void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule);

void GetCallApi(int ApiIndex, ...);


// proclaim of hook api
BOOL newIsDebuggerPresent();
DWORD newGetFileAttributesA(LPCTSTR lpFileName);
LONG newRegOpenKeyExA(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

APIINFO oriapi[MAX_ORIAPI];
