/*!
 * checkSE.c
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "checkSE.h"

int CheckSE(APIINFO *info){

	if (SEExample(info)) {
		return SE_EXAMPLE;
	}

	return SE_NONE;
}

// an example function which detect one of SE methods
int SEExample(APIINFO *info){
	if (strcmp(info->name, "Example") == 0) {
		return 1;
	}
	return 0;
}
