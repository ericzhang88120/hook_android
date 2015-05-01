#include "hook.h"

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
#include <android/log.h>  

#define A$r0          0x0
#define A$r1          0x1
#define A$r2          0x2
#define A$r3          0x3

#define A$r4          0x4
#define A$r5          0x5
#define A$r6          0x6
#define A$r7          0x7
#define A$r8          0x8
#define A$r9          0x9
#define A$r10         0xA
#define A$r11         0xB
#define A$r12         0xC

#define A$r13         0xD
#define A$r14         0xE
#define A$r15         0xF

#define A$sp          A$r13
#define A$lr          A$r14
#define A$pc          A$r15

/* ldr rd, [rn, #im] */
#define A$ldr_rd_$rn_im$(rd, rn, im) \
    (0xe5100000 | ((im) < 0 ? 0 : 1 << 23) | ((rn) << 16) | ((rd) << 12) | abs(im))

/* blx rm */
#define A$blx_rm(rm) \
    (0xe12fff30 | (rm))

/* mov rd, rm */
#define A$mov_rd_rm(rd, rm) \
    (0xe1a00000 | ((rd) << 12) | (rm))
    

static int is_thumb(void* symbol)
{
    return !(((long)symbol & 0x1) == 0);
}

static int hook_function_arm( void* symbol, void* replace, void** original_symbol, size_t* bytes_used )
{
    if(symbol == NULL)
        return -1;
    
    uint32_t* area = (uint32_t*)symbol;
    
    const size_t used = 8;
    uint32_t  backup[8 / sizeof(uint32_t)] = { area[0], area[1] };
    
    if( original_symbol != NULL )
    {
        size_t length = 8;
        length += 2 * sizeof(uint32_t);
    
        uint32_t* buffer = (uint32_t*)mmap(NULL,
                                           length,
                                           PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_ANONYMOUS | MAP_PRIVATE,
                                           -1,
                                           0);
        
        if( buffer == MAP_FAILED )
        {
            *original_symbol = NULL;
            return -1;
        }
        
        size_t i = 0;
        for(i = 0; i < 8; ++i)
        {
            buffer[i] = backup[i];
        }
        
        buffer[8] = A$ldr_rd_$rn_im$(A$pc, A$pc, 4 - 8);
        buffer[8 + 1] = (uint32_t)(area + 8 / sizeof(uint32_t));
        
        if( mprotect(buffer, length, PROT_READ | PROT_EXEC) == -1 )
        {
            munmap(buffer, length);
            *original_symbol = NULL;
            return -1;
        }
        
        *original_symbol = buffer;
        if( bytes_used != NULL )
        {
            *bytes_used = length;
        }
        
        long page_size = sysconf(_SC_PAGESIZE);
        if( mprotect( (void*)((((long)area) / page_size ) * page_size),
                      page_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC ) == 1 )
        {
            munmap((void*)buffer, length);
            *original_symbol = NULL;
            return -1;
        }
        
        area[0] = A$ldr_rd_$rn_im$(A$pc, A$pc, 4 - 8);
        area[1] = (uint32_t)replace;
    }
    
    return 0;
}

static int hook_function_thumb( void* symbol, void* replace, void** original_symbol, size_t* bytes_used )
{
    return 0;
}

static int unhook_function_arm( void* symbol, void* original_symbol, size_t bytes_used )
{
    const size_t used = 8;
    memcpy( symbol, original_symbol, used );
    
    size_t length = bytes_used;
    munmap( original_symbol, length );
    
    return 0;
}

static int unhook_function_thumb( void* symbol, void* original_symbol, size_t bytes_used )
{
    return 0;
}

int hook_function( void* symbol, void* replace, void** original_symbol, size_t* bytes_used )
{
    if( !is_thumb(symbol) )
    {
        return hook_function_arm(symbol, replace, original_symbol, bytes_used);
    }
    else
    {
        return hook_function_thumb((void*)((long)symbol & ~0x1), replace, original_symbol, bytes_used);
    }
}

int unhook_function( void* symbol, void* original_symbol, size_t bytes_used)
{
    if( !is_thumb(symbol) )
    {
        return unhook_function_arm(symbol, original_symbol, bytes_used);
    }
    else
    {
        return unhook_function_thumb(symbol, original_symbol, bytes_used);
    }
}