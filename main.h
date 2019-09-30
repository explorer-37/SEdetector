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

int main(int argc, char *argv[]);

void printApiInfo(APIINFO *ApiInfo); // for debugging

int strnsep(char *str, char **buf, const char sep, int num_sep);
int StrToApiInfo(char *str, APIINFO *ApiInfo);
void FreeApiInfo(APIINFO *ApiInfo);
