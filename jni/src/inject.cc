#include "inject.h"
#include <sys/mman.h>

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

void* get_module_base(pid_t pid,const char* module_name)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if(pid<0)
	{
		//get local address
		snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
	}
	else
	{
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename,"r");

	if(fp!=NULL)
	{
		while(fgets(line.sizeof(line),fp))
		{
			if (strstr(line, module_name))
			{
				//compare two part

				pch = strtok(line,"-");//point to the first char
				addr = strtoul(pch,NULL,16);

				if(addr==0x8000)
				{
					addr = 0;
				}
				break;
			}
		}
		fclose(fp);
	}
	return (void*)addr;
}

void* get_remote_addr(pid_t target_pid,const char* module_name,void* local_addr)
{
	void *local_handle,*remote_handle;

	local_handle = get_module_base(-1, module_name);
	remote_handle = get_module_base(target_pid,module_name);

	void *ret_addr = (void*)((uint32_t) local_addr-(uint32_t)local_handle+(uint32_t)remote_handle);

#ifdef (__i386__)
    if (!strcmp(module_name, libc_path)) {    
        ret_addr += 2;    
    }
#endif

	return ret_addr;

	
}
#if defined(__arm__)    
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)    
{    
    uint32_t i;    
    for (i = 0; i < num_params && i < 4; i ++) {    
        regs->uregs[i] = params[i];    
    }    
    //    
    // push remained params onto stack    
    //    
    if (i < num_params) {    
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;    
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));    
    }    
    
    regs->ARM_pc = addr;    
    if (regs->ARM_pc & 1) {    
        /* thumb */    
        regs->ARM_pc &= (~1u);    
        regs->ARM_cpsr |= CPSR_T_MASK;    
    } else {    
        /* arm */    
        regs->ARM_cpsr &= ~CPSR_T_MASK;    
    }    
    
    regs->ARM_lr = 0;        
    
    if (ptrace_setregs(pid, regs) == -1     
            || ptrace_continue(pid) == -1) {    
        printf("error\n");    
        return -1;    
    }    
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED);  
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            printf("error\n");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }  
    
    return 0;    
}    
    
#elif defined(__i386__)    
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)    
{    
    regs->esp -= (num_params) * sizeof(long) ;    
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));    
    
    long tmp_addr = 0x00;    
    regs->esp -= sizeof(long);    
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));     
    
    regs->eip = addr;    
    
    if (ptrace_setregs(pid, regs) == -1     
            || ptrace_continue( pid) == -1) {    
        printf("error\n");    
        return -1;    
    }    
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED);  
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            printf("error\n");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }  
    
    return 0;    
}    
#else     
#error "Not supported"    
#endif 

int ptrace_call_wrapper(pid_t target_pid,const char* func_name,void *func_addr,long *parameters,int param_num,struct pt_regs * regs)
{
	if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
	{
		return -1;
	}

	if(ptrace_getregs(target_pid, regs) == -1)
	{
		return -1;
	}
	return 0;
}
int inject_remote_process(pid_t target_pid,const char * library_path,const char * function_name,const char * param,size_t param_size)
{
	int ret = -1;

	struct pt_regs regs,original_regs;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr; 
	long parameters[10];

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

	mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap); //get mmap address
	printf("[+] Remote mmap address: %x\n", mmap_addr); 

	//set mmap args
	parameters[0] = 0;
	parameters[1] = 0x4000;
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
	parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
	parameters[4] = 0;
	parameters[5] = 0;

	if(ptrace_call_wrapper(target_pid,"mmap",mmap_addr,parameters,6,&regs) == -1)
	{
		prinf("ptrace call fail\n");
		exit(0);
	}
	
}