#ifndef _INJECT_H_
#define _INJECT_H_
#include <sys/ptrace.h>

extern "C"{
	int inject_remote_process(pid_t target_pid,const char* library_path,const char* function_name,const char* param,size_t param_size);

	int ptrace_attach(pid_t pid );
	int ptrace_getregs(pid_t pid,struct pt_regs *regs);
}
#endif