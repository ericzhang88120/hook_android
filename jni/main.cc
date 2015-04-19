#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "src/util.h"


int main(int argc,char* argv[])
{
	if(argc != 4)
	{
		printf("Parameter num wrong\n");
		exit(1);
	}
	const char* appname = argv[1];
	const char* libso = argv[2];
	const char* funcname = argv[3];
	
	pid_t target_pid;
	printf("Debug app name %s\n",appname);
	
	target_pid = find_pid_of(appname);

	printf("Debug pid:%d\n",target_pid);

	if(-1 == target_pid)
	{
		printf("Can not find the process id \n");
		return -1;
	}

	//inject so

	
	
	return 0;
}
