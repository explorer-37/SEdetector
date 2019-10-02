/*!
 * checkSE.c
 * SEdetector - Sandbox Evasion detector
 *
 * Copyright (c) 2019, NAKAMURA Ryosuke
 * Released under the BSD 2 clause license.
 * see LICENSE.txt
 */

#include "checkSE.h"

void CheckSE(APIINFO *info, int num_info){

	// debugger
	printf("Check calling IsDebuggerPresent function...");
	if (IsCheckIsDebuggerPresent(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");

	// vmware
	printf("Check looking for registry keys of vmware...");
	if (IsCheckVmwareRegKey(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");

	printf("Check looking for files of vmware...");
	if (IsCheckVmwareFile(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");

	printf("Check looking for devices of vmware...");
	if (IsCheckVmwareDevice(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");

	// virtual box
	printf("Check looking for registry keys of virtual box...");
	if (IsCheckVboxRegKey(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");

	printf("Check looking for files of virtual box...");
	if (IsCheckVboxFile(info, num_info))
		printf("detected!\n");
	else
		printf("not detected.\n");
}

/* start debugger check */
// return nonzero value if the program looks for registry keys that is unique to vmware
int IsCheckIsDebuggerPresent(APIINFO *info, int num_info){
	int i;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_ISDEBUGGERPRESENT)
			return 1;
	}
	return 0;
}
/* end debugger check */

/* start vmware check */
// return nonzero value if the program looks for registry keys that is unique to vmware
int IsCheckVmwareRegKey(APIINFO *info, int num_info){
	int i;
	unsigned long *hKey;
	char *SubKey;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_REGOPENKEYEXA) {
			hKey = (unsigned long *)info[i].Arg[0];
			SubKey = (char *)info[i].Arg[1];
			//fprintf(stderr, "vmre\n"); // for debugging
			//fprintf(stderr, "0x%lx ", *hKey); // for debugging
			//fprintf(stderr, "%s\n", SubKey); // for debugging
			if (*hKey == HKEY_LOCAL_MACHINE) {
				if (lstrcmp(SubKey, "SOFTWARE\\VMware, Inc.\\VMware Tools") == 0)
					return 1;
			}
		}
	}
	return 0;
}

// return nonzero value if the program looks for files that is unique to vmware
int IsCheckVmwareFile(APIINFO *info, int num_info){
	int i;
	char *FileName;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_GETFILEATTRIBUTESA) {
			FileName = (char *)info[i].Arg[0];
			//fprintf(stderr, "vmfi\n"); // for debugging
			//fprintf(stderr, "%s\n", FileName); // for debugging
			if (
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") == 0
			)
				return 1;
		}
	}
	return 0;
}

// return nonzero value if the program looks for devices that is unique to vmware
int IsCheckVmwareDevice(APIINFO *info, int num_info){
	int i;
	char *FileName;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_CREATEFILEA) {
			FileName = (char *)info[i].Arg[0];
			//fprintf(stderr, "vmde\n"); // for debugging
			//fprintf(stderr, "%s\n", FileName); // for debugging
			if (
					lstrcmp(FileName, "\\\\.\\HGFS") == 0 ||
					lstrcmp(FileName, "\\\\.\\vmci") == 0
			)
				return 1;
		}
	}
	return 0;
}
/* end vmware check */

/* start virtual box check */
// return nonzero value if the program looks for registry keys that is unique to virtual box
int IsCheckVboxRegKey(APIINFO *info, int num_info){
	int i;
	unsigned long *hKey;
	char *SubKey;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_REGOPENKEYEXA) {
			hKey = (unsigned long *)info[i].Arg[0];
			SubKey = (char *)info[i].Arg[1];
			//fprintf(stderr, "vbre\n"); // for debugging
			//fprintf(stderr, "0x%lx ", *hKey); // for debugging
			//fprintf(stderr, "%s\n", SubKey); // for debugging
			if (*hKey == HKEY_LOCAL_MACHINE) {
				if (
						lstrcmp(SubKey, "SOFTWARE\\Oracle\\VirtualBox Guest Additions") == 0 ||
						lstrcmp(SubKey, "HARDWARE\\ACPI\\DSDT\\VBOX__") == 0 ||
						lstrcmp(SubKey, "HARDWARE\\ACPI\\FADT\\VBOX__") == 0 ||
						lstrcmp(SubKey, "HARDWARE\\ACPI\\RSDT\\VBOX__") == 0 ||
						lstrcmp(SubKey, "SYSTEM\\ControlSet001\\Services\\VBoxGuest") == 0 ||
						lstrcmp(SubKey, "SYSTEM\\ControlSet001\\Services\\VBoxMouse") == 0 ||
						lstrcmp(SubKey, "SYSTEM\\ControlSet001\\Services\\VBoxService") == 0 ||
						lstrcmp(SubKey, "SYSTEM\\ControlSet001\\Services\\VBoxSF") == 0 ||
						lstrcmp(SubKey, "SYSTEM\\ControlSet001\\Services\\VBoxVideo") == 0
				)
					return 1;
			}
		}
	}
	return 0;
}

// return nonzero value if the program looks for files that is unique to virtual box
int IsCheckVboxFile(APIINFO *info, int num_info){
	int i;
	char *FileName;
	for (i = 0; i < num_info; i++) {
		if (info[i].Index == IDX_GETFILEATTRIBUTESA) {
			FileName = (char *)info[i].Arg[0];
			//fprintf(stderr, "vbfi\n"); // for debugging
			//fprintf(stderr, "%s\n", FileName); // for debugging
			if (
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxdisp.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxhook.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxmrxnp.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxogl.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglarrayspu.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglcrutil.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglerrorspu.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglpackspu.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxservice.exe") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxtray.exe") == 0 ||
					lstrcmp(FileName, "C:\\WINDOWS\\system32\\vboxControl.exe") == 0 ||
					lstrcmp(FileName, "C:\\prograk files\\oracle\\virtualbox guest additions\\") == 0
			)
				return 1;
		}
	}
	return 0;
}
/* end virtual box check */
