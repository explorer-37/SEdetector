/*!
 * checkSE.h
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#pragma once

#define SE_NONE 0
#define SE_EXAMPLE 1

typedef struct ApiInfo {
	char name[256];
	void **arg;
	//uint64_t time;
} APIINFO;

int SEExample(APIINFO *info);

int CheckSE(APIINFO *info);
