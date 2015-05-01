#ifndef __INJECT_H__
#define __INJECT_H__

#include <stdio.h>    
#include <stdlib.h>    
#include <string.h>
#include <stdint.h>

#include <asm/user.h>    
#include <asm/ptrace.h> 
#include <asm/signal.h>
   
#include <sys/ptrace.h> 
#include <sys/wait.h>    
#include <sys/mman.h>   
 
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <elf.h>    
#include <errno.h>
#include <android/log.h>    

#if defined(__i386__)    
#define pt_regs         user_regs_struct    
#endif    
    
#define ENABLE_DEBUG 1    
#define DSH_DEBUG_LOGGER 1

/*    
#if ENABLE_DEBUG    
#define  LOG_TAG "INJECT"    
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)    
#define DEBUG_PRINT(format,args...) \
    LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif    
*/

#define CPSR_T_MASK     ( 1u << 5 )    
    
int ptrace_readdata(pid_t pid, const uint8_t* src, uint8_t* buf, size_t size);   
int ptrace_writedata(pid_t pid, uint8_t* dest, const uint8_t* data, size_t size);
      
int ptrace_read_cstring(pid_t pid, const uint8_t* src, char* buf);
      
#if defined(__arm__)    
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs);       
#elif defined(__i386__)    
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs);   
#else     
#error "Not supported"    
#endif    

int ptrace_getregs(pid_t pid, struct pt_regs * regs);        
    
int ptrace_setregs(pid_t pid, struct pt_regs * regs);       
    
int ptrace_continue(pid_t pid);    
    
int ptrace_attach(pid_t pid);
    
int ptrace_detach(pid_t pid);  
    
void* get_module_base(pid_t pid, const char* module_name);  
    
void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr); 
    
int find_pid_of(const char *process_name);    

int find_injected_so_of(pid_t target_pid, const char* lib_name);

char* find_process_name_of(pid_t target_pid);

void find_sub_tasks_of(pid_t target_pid, pid_t* tasks, size_t max_len);

int check_pid_valid(pid_t target_pid);
	
long ptrace_retval(struct pt_regs * regs);        
    
long ptrace_ip(struct pt_regs * regs);       
    
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs* regs);     
    
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const uint8_t* param, size_t param_size, int is_unload, void** p_sohandle);    

int inject_remote_process_load(pid_t target_pid, const char* library_path, void** p_handle);
int inject_remote_process_unload(pid_t target_pid, void* sohandle);

/**
* @brief  only call dlclose() when refcount > 1
* @return -1 when error
*         0  when success
*         1  when nothing to do
*/
int inject_remote_process_virtual_unload(pid_t target_pid, void* sohandle);

const char* get_last_error();

#endif 
/*
define
*/