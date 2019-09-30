/*!
 * checkSE.c
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "checkSE.h"

int CheckSE(APIINFO *info, int num_info){

	if (SEExample(info, num_info)) {
		return SE_EXAMPLE;
	}

	return SE_NONE;
}

// an example function which detect one of SE methods
int SEExample(APIINFO *info, int num_info){
	int i;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_INVALID_API) {
			return 1;
		}
	}
	return 0;
}
