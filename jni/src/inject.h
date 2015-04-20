#ifndef _INJECT_H_
#define _INJECT_H_
#include <sys/ptrace.h>

extern "C"{
	int inject_remote_process(pid_t target_pid,const char* library_path,const char* function_name,const char* param,size_t param_size);

	int ptrace_attach(pid_t pid );
	int ptrace_getregs(pid_t pid,struct pt_regs *regs);
	void* get_remote_addr(pid_t target_pid,const char* module_name,void* local_addr);
	void* get_module_base(pid_t pid,const char* module_name);
	int ptrace_call_wrapper(pid_t target_pid,const char* func_name,void *func_addr,long *parameters,int param_num,struct pt_regs * regs);
}
#endif