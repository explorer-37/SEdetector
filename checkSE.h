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
