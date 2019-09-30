/*!
 * checkSE.h
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#pragma once

#include <string.h>

#define SE_NONE 0
#define SE_EXAMPLE 1

#define MAX_ARG 8

#define TYPE_NONE -1
#define TYPE_INT 0
#define TYPE_ATTR16 1
#define TYPE_ATTR32 2
#define TYPE_ATTR64 3
#define TYPE_ADDR 4
#define TYPE_STR 5

#define IDX_ISDEBUGGERPRESENT 0
#define IDX_GETFILEATTRIBUTESA 1
#define IDX_OPENREGKEYEXA 2
#define IDX_INVALID_API -1

// table of num of API arguments
int numArgApi[] = {
	0, // IsDebuggerPresent
	1, // GetFileAttriburesA
	5  // RegOpenKeyExA
};

// table of type of API arguments
int typeArgApi[][MAX_ARG] = {
	{TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE}, // IsDebuggerPresent
	{TYPE_STR, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE, TYPE_NONE}, // GetFileAttributesA
	{TYPE_ADDR, TYPE_STR, TYPE_ATTR32, TYPE_ATTR32, TYPE_ADDR, TYPE_NONE, TYPE_NONE, TYPE_NONE} // RegOpenKeyExA
};

//	union u1{
//		int *arg_int;
//		unsigned short *arg_attr16;
//		unsigned int *arg_attr32;
//		unsigned long long *arg_attr64;
//		unsigned long long *arg_addr;
//		char *arg_str;
//	};

typedef struct ApiInfo {
	char *Name;
	int Index;
	void *Arg[MAX_ARG];
	//uint64_t time;
} APIINFO;

int SEExample(APIINFO *info, int num_info);

int CheckSE(APIINFO *info, int num_info);
