#include "checkSE.h"

int CheckSE(APIINFO *info){

	if (SEExample(info)) {
		return SE_EXAMPLE;
	}

	return SE_NONE;
}

// an example function which detect one of SE methods
int SEExample(APIINFO *info){
	if (info.name == "Example") {
		return 1;
	}
	return 0;
}
