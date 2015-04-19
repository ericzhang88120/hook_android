#include "inject.h"

const char *libc_path = "/system/lib/libc.so";
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

	if(WIFSTOPPED(status))
	{
		printf("child stopped,signal num = %d\n",WSTOPSIG(status));
	}

	return 0;
}

int ptrace_getregs(pid_t pid,struct pt_regs *regs)
{
	if(ptrace(PTRACE_GETREGS,pid,NULL,regs)<0)
	{
		perror("ptrace_getregs :Can not get register values");
		return -1;
	}
	return 0;
}

int inject_remote_process(pid_t target_pid,const char * library_path,const char * function_name,const char * param,size_t param_size)
{
	int ret = -1;

	struct pt_regs regs,original_regs;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr; 

	printf("Debug: start to inject process %d\n",target_pid);

	if(-1 == ptrace_attach(target_pid))
	{
		printf("Debug: attach process fail\n");
		exit(0);
	}

	if(-1 == ptrace_getregs(target_pid,&regs))
	{
		printf("Debug: get process regs fail\n");
		exit(0);
	}

	//save orignal registers
	memcpy(&original_regs,&regs,sizeof(regs));

	mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap); 
	
}