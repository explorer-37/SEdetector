#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

void ModifyIat(char *dllname, void *newaddr, void *oldaddr);
PIMAGE_IMPORT_DESCRIPTOR GetImportEntry(PVOID Base, PULONG Size);
void ModifyIatOne(char *dllname, void *newaddr, void *oldaddr, HMODULE hModule);

void GetCallApi(char *apiname, ...);


// proclaim of hook api
BOOL newIsDebuggerPresent();
FARPROC oriIsDebuggerPresent;
INT newShellAboutW(HWND hWnd, LPCWSTR szApp, LPCWSTR szOtherStuff, HICON hIcon);
FARPROC oriShellAboutW;
