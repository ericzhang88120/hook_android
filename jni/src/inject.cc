#include "inject.h"

int ptrace_attach(pid_t pid )
{
	int ret = -1;

	if(ptrace(PTRACE_ATTACH,pid,NULL,0)<0)
	{
		perror("ptrace_attach");
		return ret;
	}

	int status = 0;
	waitpid(pid,&status,WUNTRACED);

	return 0;
}

int inject_remote_process(pid_t target_pid,const char * library_path,const char * function_name,const char * param,size_t param_size)
{
	int ret = -1;

	printf("Debug: start to inject process %d\n",target_pid);

	if(-1 == ptrace_attach(target_pid))
	{
		printf("Debug: attach process fail\n");
		exit(0);
	}

	
}