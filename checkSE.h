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

#define MAX_APINAME 256

typedef struct ApiInfo {
	char name[MAX_APINAME];
	union u {
		int arg_int;
		unsigned long long arg_addr;
		unsigned short arg_attr16;
		unsigned int arg_attr32;
		unsigned long long arg_attr64;
		char *str;
	} *u;
	//uint64_t time;
} APIINFO;

int SEExample(APIINFO *info);

int CheckSE(APIINFO *info);
