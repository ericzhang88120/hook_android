#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "src/inject.h"
#include "src/hook.h"


int main(int argc,char* argv[])
{
	
	pid_t target_pid;
	
	target_pid = find_pid_of("/data/local/tmp/hello");

	printf("Debug pid:%d\n",target_pid);

	if(-1 == target_pid)
	{
		printf("Can not find the process id \n");
		return -1;
	}

	const char* param = "I'm parameter!";

	void* pSohandle;
	//inject so
	if(inject_remote_process(target_pid,"/data/local/tmp/libhello.so","hook_entry",(uint8_t*)param, strlen("I'm parameter!"),0,&pSohandle)==-1)
	{
		printf("%s\n",get_last_error());
	}
	return 0;
	
	
	return 0;
}

