#include "inject.h"   
#include "linker.h"
#include <stddef.h>

#define DEAD_BEEF  0x00000000

const char *libc_path = "/system/lib/libc.so";    
const char *linker_path = "/system/bin/linker";    
    
//static const unsigned int error_length = 4096;    
static char last_error_string[4096] = {0};    

void set_last_error(const char* error)
{
    memset(last_error_string, 0, sizeof(last_error_string));
    strncpy(last_error_string, error, sizeof(last_error_string));
    
    last_error_string[sizeof(last_error_string) - 1] = '\0';
}

const char* get_last_error()
{
    return last_error_string;
}
    
static void print_registers(struct pt_regs* regs)
{
    printf("r0 %08lx r1 %08lx r2 %08lx r3 %08lx\n", regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3);
    printf("r4 %08lx r5 %08lx r6 %08lx r7 %08lx\n", regs->ARM_r4, regs->ARM_r5, regs->ARM_r6, regs->ARM_r7);
    printf("r8 %08lx r9 %08lx sl %08lx fp %08lx\n", regs->ARM_r8, regs->ARM_r9, regs->ARM_r10, regs->ARM_fp);
    printf("ip %08lx sp %08lx lr %08lx pc %08lx\n", regs->ARM_ip, regs->ARM_sp, regs->ARM_lr, regs->ARM_pc);
}
    
int ptrace_readdata(pid_t pid, const uint8_t* src, uint8_t* buf, size_t size)    
{    
    while(size >= sizeof(long))
    {
        long ret = ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
        if(ret == -1)
            if(errno)
                return -1;
        
        //@ Linux Arm (SIGBUS) of Memory Align
        //@ Use memcpy instead
        //@ *(long*)buf = ret;
        memcpy(buf, &ret, sizeof(ret));
        
        src += sizeof(long);
        buf += sizeof(long);
        size -= sizeof(long);
    }
    
    if(size > 0) 
    {
        long ret = ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
        if(ret == -1)
            if(errno)
                return -1;
            
        memcpy(buf, &ret, size);
    }
    
    return 0;    
}    
    
int ptrace_writedata(pid_t pid, uint8_t *dest,const uint8_t *data, size_t size)    
{
    while(size >= sizeof(long))
    {
        long ret = ptrace(PTRACE_POKETEXT, pid, dest, *(long*)data);
        if(ret == -1)
            if(errno)
                return -1;
        
        data += sizeof(long);
        dest += sizeof(long);
        size -= sizeof(long);
    }
    
    if(size > 0)
    {
        long value = 0;
        memcpy(&value, data, size);
        
        long ret = ptrace(PTRACE_POKETEXT, pid, dest, value);
        if(ret == -1)
            if(errno)
                return -1;
    }
    
    return 0;    
}    

int ptrace_read_cstring(pid_t pid, const uint8_t* src, char* buf)
{  
    const char terminal = '\0';
     
    do
    {
        char buffer[5] = { terminal };
        long ret = ptrace_readdata(pid, src, (uint8_t*)buffer, sizeof(long));
        
        if(ret == -1)
        {
            *buf = terminal;
            
#if DSH_DEBUG_LOGGER == 1
            perror("ptrace_read_cstring error ");
#endif           
            break;
        }
        
        strcat(buf, buffer);
        
        if(buffer[0] == terminal || buffer[1] == terminal || buffer[2] == terminal || buffer[3] == terminal)
            break;
        
        src += sizeof(long);
        
    } while(1);
   
    return 0;
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
        ptrace_writedata(pid, (uint8_t*)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));    
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
    
    regs->ARM_lr = DEAD_BEEF;        
    
    if (ptrace_setregs(pid, regs) == -1)
    {
        printf("ptrace setregs[0] error\n");    
        return -1;
    }
    
    if(ptrace_continue(pid) == -1) 
    {    
        printf("ptrace continue[0] error\n");    
        return -1;    
    }
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED); 
    
    while ( !(SIGSEGV == WSTOPSIG(stat) && WIFSTOPPED(stat)) ) {
        if (ptrace_continue(pid) == -1) {  
            printf("ptrace continue[1] error\n");  
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
    ptrace_writedata(pid, (char*)regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));     
    
    regs->eip = DEAD_BEEF;    
    
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
    
int ptrace_getregs(pid_t pid, struct pt_regs* regs)
{    
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {    
        perror("ptrace_getregs: Can not get register values");    
        return -1;    
    }    
    
    return 0;    
}    
    
int ptrace_setregs(pid_t pid, struct pt_regs* regs)
{    
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {  
        char error_msg[64] = {0};
        sprintf(error_msg, "ptrace_setregs [%d]", pid);
        perror(error_msg);      
        return -1;    
    }    
    
    return 0;    
}    
    
int ptrace_continue(pid_t pid)    
{    
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {    
        char error_msg[64] = {0};
        sprintf(error_msg, "ptrace_continue [%d]", pid);
        perror(error_msg);    
        return -1;    
    }    
    
    return 0;    
}    
    
int ptrace_attach(pid_t pid)    
{    
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        char error_msg[64] = {0};
        sprintf(error_msg, "ptrace_attach [%d]", pid);
        perror(error_msg);    
        return -1;    
    }    
    
    int status = 0;    
    waitpid(pid, &status , WUNTRACED);    
    
    return 0;    
}    
    
int ptrace_detach(pid_t pid)    
{    
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {    
        char error_msg[64] = {0};
        sprintf(error_msg, "ptrace_detach [%d]", pid);
        perror(error_msg);    
        return -1;    
    }    
    
    return 0;    
}    
    
void* get_module_base(pid_t pid, const char* module_name)    
{    
    FILE *fp;    
    long addr = 0;    
    char *pch;    
    char filename[32];    
    char line[1024];    
    
    if (pid < 0) {    
        /* self process */    
        snprintf(filename, sizeof(filename), "/proc/self/maps");    
    } else {    
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);    
    }
    
    fp = fopen(filename, "r");    
    
    if (fp != NULL) {    
        while (fgets(line, sizeof(line), fp)) {    
            if (strstr(line, module_name)) {    
                pch = strtok( line, "-" );    
                addr = strtoul( pch, NULL, 16 );    
    
                if (addr == 0x8000)    
                    addr = 0;    
    
                break;    
            }    
        }    
    
        fclose(fp) ;    
    }    
    
    return (void *)addr;    
}    
    
void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)    
{    
    void* local_handle, *remote_handle;    
    
    local_handle = get_module_base(-1, module_name);    
    remote_handle = get_module_base(target_pid, module_name);       
    
    void * ret_addr = (void *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);    
    
#if defined(__i386__)    
    if (!strcmp(module_name, libc_path)) {    
        ret_addr += 2;    
    }    
#endif    
    return ret_addr;    
}    
    
int find_pid_of(const char *process_name)    
{    
    int id;    
    pid_t target_pid = -1;    
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    char cmdline[256];    
    
    struct dirent* entry;    
    
    if (process_name == NULL)    
    {
    	printf("process name wrong");
        return -1;    
    }
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return -1;    
    
    int zygote_id = 0;
    
    int index = 0;
    int pids[16] = {0};
    
    while((entry = readdir(dir)) != NULL) {    
        id = atoi(entry->d_name);    
        if (id != 0) {    
            sprintf(filename, "/proc/%d/cmdline", id);    
            fp = fopen(filename, "r");    
            
            if (fp) {    
                fgets(cmdline, sizeof(cmdline), fp);    
                fclose(fp);    
                /** find zygote */
                /*
                if (zygote_id == 0 && strncmp(cmdline, "zygote", strlen("zygote")) == 0  )
                {
                    zygote_id = id;
                    continue;
                }*/
    
                if (strcmp(process_name, cmdline) == 0) {    
                    /* process found */    
                    //pids[index++] = id;
                    target_pid = id;
                    //continue;
                    break;
                }    
            }    
        }    
    }
    
    /** find process launched by zygote */
    /*
    int i=0;
    for(i = 0; i!= index; ++i)
    {
        sprintf(filename, "/proc/%d/stat", pids[i]);
        fp = fopen(filename, "r");
        
        
        if(fp) {
            
            fgets(cmdline, sizeof(cmdline), fp);
            fclose(fp);
            
            int pid, ppid;
            char processname[64];
            char state;
            char other[512];
            
            sscanf(cmdline, "%d %s %c %d %s", &pid, processname, &state, &ppid, other);
            
            if( ppid == zygote_id && pid == pids[i])
            {
                target_pid = pids[i];
                break;
            }
        }
    }
*/
    closedir(dir);    
    return target_pid;    
}    

int find_injected_so_of(pid_t target_pid, const char* lib_name)
{
	char filename[32] = {0};
	char so_name[1024] = {0};
	
	DIR* dir = NULL;
	
	if((dir = opendir("/proc")) != NULL)
	{
		if(lib_name != NULL)
		{
            if(target_pid == -1)
                sprintf(filename, "/proc/self/maps");
            else
                sprintf(filename, "/proc/%d/maps", target_pid);
            
			FILE* fp = fopen(filename, "r");
			
			if(fp != NULL)
			{
				while(1)
				{
					if( !fgets(so_name, sizeof(so_name), fp) )
					{
						fclose(fp);
						printf("cannot found injected so %s\n", filename);
						closedir(dir);
						
						return 0;
					}
					
					if( strstr(so_name, lib_name) )
						break;
					
					memset(so_name, 0, sizeof(so_name));
				}
				
				printf("[+] injected so found %d\n", target_pid);
				fclose(fp);
				closedir(dir);
				
				return 1;
			}
			else
			{
				printf("open map file error : %s\n", filename);
				closedir(dir);
				
				return 0;
			}
		}
		else
		{
			closedir(dir);
			
			return 0;
		}
	}
	else
	{
		return 0;
	}
}
	
char* find_process_name_of(pid_t target_pid)
{
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    
    static char cmdline[256];    
    
    struct dirent* entry;    
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return "";    
    
    int index = 0;
    
    while((entry = readdir(dir)) != NULL) {    
        int id = atoi(entry->d_name);   

        if( (unsigned)id == target_pid )
        {
            sprintf(filename, "/proc/%d/cmdline", id);    
            fp = fopen(filename, "r"); 
            
            if( fp != NULL )
            {
                memset(cmdline, '\0', sizeof(cmdline));
                
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                
                return cmdline;
            }
            
            break;
        }      
    }
    
    return "";
}    

void find_sub_tasks_of(pid_t target_pid, pid_t* tasks, size_t max_len)
{
    if(tasks == NULL)
        return ;
    
    DIR* dir;
    FILE* fp;
    
    char filename[128] = {0};
    sprintf(filename, "/proc/%d/task", (int)target_pid);
    
    dir = opendir(filename);
    if(dir == NULL)
        return;
    
    pid_t* end = tasks + max_len;
    
    struct dirent* entry;
    while( (entry = readdir(dir)) != NULL )
    {
        int id = atoi(entry->d_name);
        
        if( (unsigned)id != target_pid )
        {
            if(tasks != end)
            {
                *tasks++ = (unsigned)id;
            }
        }
    }
    
    closedir(dir);
}
    
int check_pid_valid(pid_t target_pid)
{
    DIR* dir = NULL;
	struct dirent* entry = NULL;
    
	if((dir = opendir("/proc")) != NULL)
    {
        while((entry = readdir(dir)) != NULL)
        {
            int id = atoi(entry->d_name);
            
            if( id == (int)target_pid )
            {
                return 1;
            }
        }
    }
    
    return 0;
}    
    
long ptrace_retval(struct pt_regs * regs)    
{    
#if defined(__arm__)    
    return regs->ARM_r0;    
#elif defined(__i386__)    
    return regs->eax;    
#else    
#error "Not supported"    
#endif    
}    
    
long ptrace_ip(struct pt_regs * regs)    
{    
#if defined(__arm__)    
    return regs->ARM_pc;    
#elif defined(__i386__)    
    return regs->eip;    
#else    
#error "Not supported"    
#endif    
}    
    
int ptrace_call_wrapper(pid_t target_pid, const char* func_name, void* func_addr, long* parameters, int param_num, struct pt_regs* regs)     
{      
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)    
        return -1;    
    
    if (ptrace_getregs(target_pid, regs) == -1)    
        return -1;      
    return 0;    
}    

int remote_mmap_call(pid_t target_pid, struct pt_regs* p_regs,
                     void* addr,
                     size_t size,
                     int prot,
                     int flags,
                     int fd,
                     off_t offset,
                     void** result)
{
    
    long parameters[6] = {0};
    
    parameters[0] = (long)addr;
    parameters[1] = (long)size;
    parameters[2] = (long)prot;
    parameters[3] = (long)flags;
    parameters[4] = (long)fd;
    parameters[5] = (long)offset;
    
    void* mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_mmap [%08x]\n", (unsigned int)mmap_addr);
#endif    
    if(ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, p_regs) == -1)
    {
        set_last_error("remote call error : mmap");
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
    }
    
    return 0;
}

int remote_dlopen_call(pid_t target_pid, struct pt_regs* p_regs,
                       const char* pathname,
                       int mode,
                       void** result)
{
    
    long parameters[2] = {0};
    
    parameters[0] = (long)pathname;
    parameters[1] = (long)mode;
    
    void* dlopen_addr = get_remote_addr( target_pid, linker_path, (void*)dlopen );    
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_dlopen [%08x]\n", (unsigned int)dlopen_addr);
#endif    
    if(ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, p_regs) == -1)
    {
#if DSH_DEBUG_LOGGER == 1
        printf("%s", "remote dlopen error!\n");
#endif    
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
        
#if DSH_DEBUG_LOGGER == 1        
        printf("%s", "[+] ======= So Info List ========.\n");
        
        int ret = 0;
        long word = 0;
        
        struct soinfo* si = *result;
        
        /** Print So Info */
        printf("handle %08x\n", (int32_t)si);
        
        char name[128] = {0};
        long base = 0;
        long size = 0;
        long flags = 0;
        long refcount = 0;
        
        ret = ptrace_read_cstring(target_pid, (const uint8_t*)(si) + offsetof(soinfo, name), name);
        
        ret = ptrace_readdata(target_pid, (const uint8_t*)(si) + offsetof(soinfo, base), (uint8_t*)&word, sizeof(word));
        if(ret != -1)
            base = word;
    
        ret = ptrace_readdata(target_pid, (const uint8_t*)(si) + offsetof(soinfo, size), (uint8_t*)&word, sizeof(word));
        if(ret != -1)
            size = word;
    
        ret = ptrace_readdata(target_pid, (const uint8_t*)(si) + offsetof(soinfo, flags), (uint8_t*)&word, sizeof(word));
        if(ret != -1)
            flags = word;

        ret = ptrace_readdata(target_pid, (const uint8_t*)(si) + offsetof(soinfo, refcount), (uint8_t*)&word, sizeof(word));
        if(ret != -1)
            refcount = word;
        
        printf("name  base  size  flags  refcount\n");
        printf("%s 0x%08lx %ld %ld %ld\n", name, base, size, flags, refcount);
    }   
#endif     
    
    return 0;
}

int remote_dlsym_call(pid_t target_pid, struct pt_regs* p_regs,
                      void* handle,
                      const char* symbol,
                      void** result)
{
    
    long parameters[2] = {0};
    
    parameters[0] = (long)handle;
    parameters[1] = (long)symbol;
    
    void* dlsym_addr = get_remote_addr( target_pid, linker_path, (void*)dlsym );    

#if DSH_DEBUG_LOGGER == 1
    printf("remote_dlsym [%08x]\n", (unsigned int)dlsym_addr);
#endif      
    if(ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, p_regs) == -1)
    {
#if DSH_DEBUG_LOGGER == 1
        printf("%s", "remote dlsym error!\n");
#endif  
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
    }
    
    return 0;
}

int remote_dlclose_call(pid_t target_pid, struct pt_regs* p_regs,
                        void* handle,
                        void** result)
{
    const size_t parameters_number = 1;
    
    long parameters[1] = {0};
    
    parameters[0] = (long)handle;
    
    void* dlclose_addr = get_remote_addr( target_pid, linker_path, (void*)dlclose );    
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_dlclose [%08x]\n", (unsigned int)dlclose_addr);
#endif        
    if(ptrace_call_wrapper(target_pid, "dlclose", dlclose_addr, parameters, parameters_number, p_regs) == -1)
    {
#if DSH_DEBUG_LOGGER == 1
        printf("%s", "remote dlclose error!\n");
#endif  
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
    }
    
    return 0;
}

int remote_dlerror_call(pid_t target_pid, struct pt_regs* p_regs,
                        void** result)
{
    static char error_message[4096] = {0};
    
    const size_t parameters_number = 0;
    
    void* dlerror_addr = get_remote_addr( target_pid, linker_path, (void*)dlerror );
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_dlerror [%08x]\n", (unsigned int)dlerror_addr);
#endif      
    if(ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, NULL, parameters_number, p_regs) == -1)
    {
#if DSH_DEBUG_LOGGER == 1
        printf("%s", "remote dlerror error!\n");
#endif  
        return -1;
    }
    
    memset(error_message, 0, sizeof(error_message));
    
    if(result != NULL)
    {
        long address = ptrace_retval(p_regs);
        
        if(address != 0)
        {            
            ptrace_read_cstring(target_pid, (const uint8_t*)address, error_message);
        }
        
        *result = (void*)error_message;
    }
    
    return 0;
}

int remote_munmap_call(pid_t target_pid, struct pt_regs* p_regs,
                       void* start,
                       size_t length,
                       void** result)
{
    const size_t parameters_number = 2;
    
    long parameters[2] = {0};
    
    parameters[0] = (long)start;
    parameters[1] = (long)length;
       
    void* munmap_addr = get_remote_addr(target_pid, libc_path, (void*)munmap);
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_munmap [%08x]\n", (unsigned int)munmap_addr);
#endif       
    if(ptrace_call_wrapper(target_pid, "munmap", munmap_addr, parameters, parameters_number, p_regs) == -1)
    {
//       set_last_error("remote call error : munmap");
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
    }
    
    return 0;
}

int remote_hookentry_call(pid_t target_pid, struct pt_regs* p_regs,
                          void* hook_entry_addr,
                          void* params,
                          size_t size,
                          void** result)
{
    const size_t parameters_number = 2;
    
    long parameters[2] = {0};
    
    parameters[0] = (long)params;
    parameters[1] = (long)size;
    
#if DSH_DEBUG_LOGGER == 1
    printf("remote_hookentry [%08x]\n", (unsigned int)hook_entry_addr);
#endif      
    if(ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, parameters_number, p_regs) == -1)
    {
        set_last_error("remote call error : hook_entry");
        return -1;
    }
    
    if(result != NULL)
    {
        *result = (void*)ptrace_retval(p_regs);
    }
    
    return 0;
}
    
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const uint8_t* param, size_t param_size, int is_unload, void** p_sohandle)    
{    
    int ret = -1;    
    struct pt_regs regs, original_regs;   
   
    if (ptrace_attach(target_pid) == -1)
        return ret;    
    
    printf("%s", "[+] attach success.\n");
    
    if (ptrace_getregs(target_pid, &regs) == -1)
        return ret;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));    
    
    printf("%s", "[+] save register success.\n");
    printf("%s",  "[-] print registers\n");
    print_registers(&original_regs);
    
    /** call mmap **/
    void* map_base = NULL;
    if(remote_mmap_call(target_pid, &regs,
                        0,                                 /* addr */
                        0x4000,                            /* size */
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE,
                        0,                                 /* fd */
                        0,                                 /* offset */
                        &map_base
                        ) == -1 
    )
    {
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
                       
    if(map_base == NULL)
    {
        set_last_error("remote mmap call : return NULL");
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    printf("%s", "[+] mmap success.\n");
    
#define LIBRARY_NAME_ADDR_OFFSET       0x0  
    ptrace_writedata(target_pid, (uint8_t*)map_base + LIBRARY_NAME_ADDR_OFFSET, (const uint8_t*)library_path, strlen(library_path) + 1);    
    
    /** call dlopen */
    void* sohandle = NULL;
    if(remote_dlopen_call(target_pid, &regs,
                          (const char*)map_base,         /* name */
                          RTLD_NOW | RTLD_GLOBAL,        /* mode */
                          &sohandle
                          ) == -1
    )
    {
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    /** validate dlopen returned-value */
    if(sohandle == NULL)
    {
        /** dlerror */
        void* dlerror_message = NULL;
        remote_dlerror_call(target_pid, &regs,
                            &dlerror_message
                            );
        
        set_last_error((const char*)dlerror_message);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    printf("%s", "[+] dlopen success.\n");
                          
#define FUNCTION_NAME_ADDR_OFFSET       0x100    
    ptrace_writedata(target_pid, (uint8_t*)map_base + FUNCTION_NAME_ADDR_OFFSET, (const uint8_t*)function_name, strlen(function_name) + 1);  

    /** call dlsym */
    void* hook_entry_addr = NULL;
    if(remote_dlsym_call(target_pid, &regs,
                         sohandle,         /* handle */
                         (const char*)((uint8_t*)map_base + FUNCTION_NAME_ADDR_OFFSET),  /* function name */
                         &hook_entry_addr
                         ) == -1 
    )
    {
        /** dlclose */
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }        
    
    /** validate dlsym returned-value */
    if(hook_entry_addr == NULL)
    {
        /** dlerror */
        void* dlerror_message = NULL;
        remote_dlerror_call(target_pid, &regs,
                            &dlerror_message
                            );
        
        set_last_error((const char*)dlerror_message);
        
        /** dlclose */
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    printf("%s address = %p\n", function_name, hook_entry_addr);
	
#define FUNCTION_PARAM_ADDR_OFFSET      0x200    
    ptrace_writedata(target_pid, (uint8_t*)map_base + FUNCTION_PARAM_ADDR_OFFSET, param, param_size);    
    
    /** call hook_entry */
    void* hook_entry_returned = NULL;
    if(remote_hookentry_call(target_pid, &regs, hook_entry_addr, 
                             (uint8_t*)map_base + FUNCTION_PARAM_ADDR_OFFSET,   /* params */
                             param_size, /* params_size */
                             &hook_entry_returned
                             ) == -1
    )
    {
        /** dlclose */
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    /** validate hook_entry returned-value */
    if((long)hook_entry_returned == -1)
    {
        char error_message[1024] = {0};
        sprintf(error_message, "remote %s call : return -1", function_name);
        
        set_last_error(error_message);
        
        /** dlclose */
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
    
        return ret;
    }
    
    printf("[+] %s success.\n", function_name);
    
    /** do not dlclose if is_unload == false */
    if(is_unload)
    {
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
    }
    else
    {
        /** set sohandle */
        if(p_sohandle != NULL)
        {
            *p_sohandle = sohandle;
        }
    }
    
    /** munmap */
    remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
    print_registers(&original_regs);    
    /** restore and detach */
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);

    printf("%s", "[+] detach success.\n");
    
    ret = 0;
    return ret;
}

int inject_remote_process_load(pid_t target_pid, const char *library_path, void** p_handle)
{
    int ret = -1;    

    struct pt_regs regs, original_regs;   
   
    if (ptrace_attach(target_pid) == -1)
        return ret;    
    
    printf("%s", "[+] attach success.\n");
    
    if (ptrace_getregs(target_pid, &regs) == -1)
        return ret;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));    
    
    printf("%s", "[+] save register success.\n");
    printf("%s",  "[-] print registers\n");
    print_registers(&original_regs);
    
    /** call mmap **/
    void* map_base = NULL;
    if(remote_mmap_call(target_pid, &regs,
                        0,                                 /* addr */
                        0x4000,                            /* size */
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE,
                        0,                                 /* fd */
                        0,                                 /* offset */
                        &map_base
                        ) == -1 
    )
    {
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
                       
    if(map_base == NULL)
    {
        set_last_error("remote mmap call : return NULL");
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    printf("%s", "[+] mmap success.\n");
    
#define LIBRARY_NAME_ADDR_OFFSET       0x0  
    ptrace_writedata(target_pid, (uint8_t*)map_base + LIBRARY_NAME_ADDR_OFFSET, (const uint8_t*)library_path, strlen(library_path) + 1);
    
    /** call dlopen */
    void* sohandle = NULL;
    if(remote_dlopen_call(target_pid, &regs,
                          (const char*)map_base,         /* name */
                          RTLD_NOW | RTLD_GLOBAL,        /* mode */
                          &sohandle
                          ) == -1
    )
    {
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    /** validate dlopen returned-value */
    if(sohandle == NULL)
    {
        /** dlerror */
        void* dlerror_message = NULL;
        remote_dlerror_call(target_pid, &regs,
                            &dlerror_message
                            );
        
        set_last_error((const char*)dlerror_message);
        
        /** munmap */
        remote_munmap_call(target_pid, &regs, map_base, 0x4000, NULL);
        
        /** restore and detach */
        ptrace_setregs(target_pid, &original_regs);    
        ptrace_detach(target_pid); 
        
        return ret;
    }
    
    if(p_handle != NULL)
        *p_handle = sohandle;
    
    printf("%s", "[+] dlopen success.\n");
    
    /** restore and detach */
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);
    
    ret = 0;
    return ret;
}

int inject_remote_process_unload(pid_t target_pid, void* sohandle)
{
    int ret = -1;    

    struct pt_regs regs, original_regs;   
   
    if (ptrace_attach(target_pid) == -1)
        return ret;    
    
    if (ptrace_getregs(target_pid, &regs) == -1)
        return ret;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));
    
    if(sohandle != NULL)
    {
        /** unload */
        remote_dlclose_call(target_pid, &regs, sohandle, NULL);
        
        printf("%s", "[+] dlclose success.\n");
    }
    
    /** restore and detach */
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);
        
    ret = 0;
    return ret;
}

int inject_remote_process_virtual_unload(pid_t target_pid, void* sohandle)
{
    int ret = -1;    
    struct pt_regs regs, original_regs;  
    
    if (ptrace_attach(target_pid) == -1)
        return ret;    
    
    if (ptrace_getregs(target_pid, &regs) == -1)
        return ret;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));
    
    if(sohandle != NULL)
    {
        /** check whether refcount > 1 */
        int p_ret = 0;
        long word = 0;
        p_ret = ptrace_readdata(target_pid, (const uint8_t*)sohandle + offsetof(soinfo, refcount), (uint8_t*)&word, sizeof(word));
        
        if(p_ret == -1)
        {
            perror("read reference count error");
            
            /** restore and detach */
            ptrace_setregs(target_pid, &original_regs);    
            ptrace_detach(target_pid);
        
            ret = -1;
            return ret;
        }
        
        /** if refcount > 1 then dlclose will not unload library but let refcount minus 1 */
        if( (unsigned)word > 1 )
        {
            /** unload */
            remote_dlclose_call(target_pid, &regs, sohandle, NULL);
            
            printf("%s", "[+] dlclose success.\n");
            
            /** restore and detach */
            ptrace_setregs(target_pid, &original_regs);    
            ptrace_detach(target_pid);
        
            ret = 0;
            return ret;
        }
    }
    
    /** restore and detach */
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);
        
    ret = 1;
    return ret;
}
