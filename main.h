/*!
 * main.h
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "CheckSE.h"

#define DLLPATH "apimonitor.dll"

#define PIPE_BUFFER 65536
#define MAX_STR PIPE_BUFFER
#define MAX_BUF 256

#define MAX_HOOKED_API 1024

// table of num of API arguments
int numArgApi[] = {
	0, // IsDebuggerPresent
	1, // GetFileAttriburesA
	5, // RegOpenKeyExA
	7  // CreateFileA
};

// table of type of API arguments
int typeArgApi[][MAX_ARG] = {
	{TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE}, // IsDebuggerPresent
	{TYPE_STR, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE}, // GetFileAttributesA
	{TYPE_ADDR, TYPE_STR, TYPE_ATTR32, TYPE_ATTR32, TYPE_ADDR, TYPE_NONE, TYPE_NONE, TYPE_NONE}, // RegOpenKeyExA
	{TYPE_STR, TYPE_ATTR32, TYPE_ATTR32, TYPE_ADDR, TYPE_ATTR32, TYPE_ATTR32, TYPE_ADDR, TYPE_NONE} // CreateFileA
};

#define GetTypeArgument(_index, _arg) typeArgApi[_index][_arg]
//	int GetTypeArgument(int index, int arg){
//	return typeArgApi[index][arg];
//}
#define GetNumArgument(_index) numArgApi[_index]
//int GetNumArgument(int index){
//	return numArgApi[index];
//}

int main(int argc, char *argv[]);

void printApiInfo(APIINFO *ApiInfo); // for debugging

int strnsep(char *str, char **buf, const char sep, int num_sep);
int StrToApiInfo(char *str, APIINFO *ApiInfo);
void FreeApiInfo(APIINFO *ApiInfo);
