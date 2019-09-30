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

// check if the program peeks registry key that is unique in vmware
int CheckVmwareRegKey(APIINFO *info, int num_info){
	int i;
	for (i = 0; i < num_info; i++) {
		if (info[i]->Index == IDX_REGOPENKEYEXA) {
			unsigned long long *hKey = (unsigned long long *)info[i]->Arg[0];
			char *SubKey = (char *)info[i]->Arg[1];
			if (*hKey == HKEY_LOCAL_MACHINE) {
				if (
						strncmp(SubKey, "SOFTWARE\\VMware, Inc.\\VMware Tools", MAX_BUF) == 0 ||
						strncmp(SubKey, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", MAX_BUF) == 0 ||
						strncmp(SubKey, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", MAX_BUF) == 0 ||
						strncmp(SubKey, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", MAX_BUF) == 0
				)
					return 1;
			}
		}
	}
	return 0;
}

// an example function which detect one of SE methods
int SEExample(APIINFO *info, int num_info){
	int i;
	for (i = 0; i < num_info; i++) {
		if (info[i]->Index == IDX_INVALID_API) {
			return 1;
		}
	}
	return 0;
}
