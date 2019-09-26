#include <stdio.h>
#include <windows.h>

int main(){
	unsigned int pid = (unsigned int)GetCurrentProcessId();
	printf("pid = %d\n", pid);

	if(IsDebuggerPresent())
		printf("debugged!\n");
	else
		printf("not debugged.\n");
	return 0;
}
