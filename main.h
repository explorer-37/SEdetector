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
#include <windows.h>

#include "CheckSE.h"

#define DLLPATH "apimonitor.dll"

#define PIPE_BUFFER 65536
#define MAX_STR PIPE_BUFFER
#define MAX_BUF 256

#define TYPE_INT 0
#define TYPE_ATTR16 1
#define TYPE_ATTR32 2
#define TYPE_ATTR64 3
#define TYPE_ADDR 4
#define TYPE_STR 5

int main(int argc, char *argv[]);

int strnsep(char *str, char **buf, const char sep, int num_sep);
void StrToApiInfo(char *str, APIINFO *ApiInfo);
void ClearApiInfo(APIINFO *ApiInfo);
