#include <unistd.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <android/log.h>  
#include <elf.h>  
#include <fcntl.h>  
#include "include/hook.h"
  
#define LOG_TAG "DEBUG"  
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)    

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

int newprint()
{
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

	return 0;
}

int hook_entry(char * a){  
	void* baseptr = get_module_base(getpid(),"libtarget.so");

	void* handle = dlopen("/data/local/tmp/libtarget.so",RTLD_LAZY);

	void *oldptr = dlsym(handle,"helloprint");
	printf("I use the old func\n");
	((int(*)())oldptr)();
	printf("old ptr %p\n",oldptr);
	printf("=================\n");
	void *newptr = (void*)newprint;
	void* symbolptr;

	size_t byteused;

	printf("new : %p\n", (unsigned int)newprint);
	//((int(*)())newptr)();

	if(hook_function(oldptr,newptr,&symbolptr,&byteused)==-1)
	{
		printf("%s\n","ERROR");									
	}

	//unhook_function(oldptr,symbolptr,byteused);
    return 0;  
}



