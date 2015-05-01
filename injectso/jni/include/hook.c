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

#define A$ldr_rd_$rn_im$(rd, rn, im) \
    (0xe5100000 | ((im) < 0 ? 0 : 1 << 23) | ((rn) << 16) | ((rd) << 12) | abs(im))

#define A$blx_rm(rm) \
    (0xe12fff30 | (rm))

#define A$mov_rd_rm(rd, rm) \
    (0xe1a00000 | ((rd) << 12) | (rm))
   
#define T$push_r(reg) \
    (0xb400 | (((reg) & (1 << A$lr)) >> A$lr << 8) | ((reg) & 0xff))

#define T$pop_r(reg) \
    (0xbc00 | (((reg) & (1 << A$pc)) >> A$pc << 8) | ((reg) & 0xff))

#define T$bx(reg) \
    (0x4700 | (reg << 3))
    
#define T$blx(reg) \
    (0x4780 | (reg << 3))
        
#define T$nop \
    (0x46c0)
        
#define T$mov_rd_rm(rd, rm) \
    (0x4600 | (((rd) & 0x8) >> 3 << 7) | (((rm) & 0x8) >> 3 << 6) | (((rm) & 0x7) << 3) | ((rd) & 0x7))

#define T$ldr_rd_pc_inc_4(rd, inc) \
    (0x4800 | ((rd) << 8) | ((inc) & 0xff))    
        
static int is_thumb(void* symbol)
{
    return !(((long)symbol & 0x1) == 0);
}

static int is_thumb_pcrel_bl(uint16_t* ins) 
{
    return (ins[0] & 0xf800) == 0xf000 && ((ins[1] & 0xd000) == 0xd000 || (ins[1] & 0xd001) == 0xc000);
}

static int is_thumb_32_bit(uint16_t ins)
{
    return ((ins & 0xe000) == 0xe000 && (ins & 0x1800) != 0x0000);
}

static size_t width_of_thumb(void* addr)
{
    uint16_t* thumb = (uint16_t*)addr;
    return is_thumb_32_bit(*thumb) ? 4 : 2;
}

static int hook_function_arm( void* symbol, void* replace, void** original_symbol, size_t* bytes_used )
{
    if(symbol == NULL)
        return -1;
    
    uint32_t* area = (uint32_t*)symbol;
    
    const size_t used = 8;
    uint32_t  backup[used / sizeof(uint32_t)] = { area[0], area[1] };
    
    if( original_symbol != NULL )
    {
        size_t length = used;
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
        for(i = 0; i != used; ++i)
        {
            buffer[i] = backup[i];
        }
        
        buffer[used] = A$ldr_rd_$rn_im$(A$pc, A$pc, 4 - 8);
        buffer[used + 1] = (uint32_t)(area + used / sizeof(uint32_t));
        
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
    }
    
    area[0] = A$ldr_rd_$rn_im$(A$pc, A$pc, 4 - 8);
    area[1] = (uint32_t)replace;
    
    return 0;
}

static int hook_function_thumb( void* symbol, void* replace, void** original_symbol, size_t* bytes_used )
{
    if(symbol == NULL)
        return -1;
    
    uint16_t* area = (uint16_t*)symbol;
    
    unsigned int align = ( (((uintptr_t)area) & (1 << 1)) == 0 ? 0 : 1 );
    
    uint16_t* thumb = area + align;
    uint32_t* arm = (uint32_t*)(thumb + 2);    
    uint16_t* trail = (uint16_t*)(arm + 2);
    
    //! maybe required = 12 ...  fuck...
    size_t required = sizeof(uint16_t) * (trail - area);
    
    //! how many bytes we actual used ... 甚至比12更大？ what the fuck...
    size_t used = 0;
    while(used < required)
    {
        used += width_of_thumb( (uint8_t*)area + used );
    }
    
    //! normally, blank = 0
    size_t blank = (used - required) / sizeof(uint16_t);
    
    uint16_t backup[used / sizeof(uint16_t)];
    memcpy(backup, area, used);
    
    if( original_symbol != NULL )
    {
        size_t length = used;
        for(unsigned int offset = 0; offset != used / sizeof(uint16_t); ++offset)
        {
            if(is_thumb_pcrel_bl(backup + offset))
            {
                length += 5 * sizeof(uint16_t);
                
                //! skip 2 bytes;
                ++offset;
            }
            else if(is_thumb_32_bit(backup[offset]))
            {
                //! skip 2 bytes;
                ++offset;
            }
        }
        
        unsigned int pad = ((length & (1 << 1)) == 0 ? 0 : 1);
        
        //! 2 thumb ins + 2 arm ins + pad
        length += pad * sizeof(uint16_t) + 2 * sizeof(uint16_t) + 2 * sizeof(uint32_t);
    
        uint16_t* buffer = (uint16_t*)mmap(NULL,
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
        
        size_t start = pad;
        size_t end = length / sizeof(uint16_t);
        uint32_t* trailer = (uint32_t*)(buffer + end);
        
        for(unsigned int offset = 0; offset != used / sizeof(uint16_t); ++offset)
        {
            //! bl instruction
            if(is_thumb_pcrel_bl(backup + offset))
            {
                //! Parse Instruction
                union
                {
                    uint16_t value;
                    
                    struct
                    {
                        uint16_t immediate : 10;
                        uint16_t s : 1,
                        uint16_t : 5;
                    };
                } first_16_bits = {backup[offset + 0]};
                
                union
                {
                    uint16_t value;
                    
                    struct
                    {
                        uint16_t immediate : 11;
                        uint16_t j2 : 1;
                        uint16_t x  : 1;
                        uint16_t j1 : 1;
                        uint16_t : 2;
                    };
                } last_16_bits = {backup[offset + 1]};
                
                int32_t distance = 0;
                
                //! set 24 bit
                distance |= first_16_bits.s << 24;
                
                //! set 23 bit
                distance |= (~(first_16_bits.s ^ last_16_bits.j1) & 0x1) << 23;
                
                //! set 22 bit
                distance |= (~(first_16_bits.s ^ last_16_bits.j2) & 0x1) << 22;
                
                //! set [12, 22) bits
                distance |= first_16_bits.immediate << 12;
                
                //! set [1, 12) bits
                distance |= last_16_bits.immediate << 1;
                
                //! set 0 bit
                distance |= last_16_bits.x;
                
                //! clear most left 7 bits; set them to 0x0
                distance <<= 7;
                distance >>= 7;
                
                /* push r7 */
                *(buffer + start) = T$push_r( 1 << A$r7 );
                
                /* ldr r7, [pc + ..] */
                *(buffer + start + 1) = T$ldr_rd_pc_inc_4( A$r7, ((sizeof(uint16_t) + ((end - sizeof(uint16_t)) - (start + 1)) * sizeof(uint16_t)) / 4) );
                
                /* mov lr, r7 */
                *(buffer + start + 2) = T$mov_rd_rm( A$lr, A$r7 );
                
                /* pop r7 */
                *(buffer + start + 3) = T$pop_r( 1 << A$r7 );
                
                /* blx lr */
                *(buffer + start + 4) = T$blx( A$lr );
                
                *--trailer = (uint32_t)(area + offset) + sizeof(uint32_t) + distance;
                
                ++offset;
                start += 5;
                end   -= sizeof(uint16_t);
            }
            else if( is_thumb_32_bit(backup[offset]) )
            {
                //! first 16 bits
                *(buffer + start) = *(backup + offset);
                ++start;
                
                //! skip 16 bits
                ++offset;
                
                //! last 16 bits
                *(buffer + start) = *(backup + offset);
                ++start;
            }
            else
            {
                *(buffer + start) = *(backup + offset);
                ++start;
            }
        }
        
        *(buffer + start) = T$bx(A$pc);
        ++start;
        
        *(buffer + start) = T$nop;
        ++start;
        
        uint32_t* back = (uint32_t*)(buffer + start);
        back[0] = A$ldr_rd_$rn_im$(A$pc, A$pc, -4);
        //! thumb 
        back[1] = (uint32_t)(area + used / sizeof(uint16_t)) + 1;
        
        if( mprotect(buffer, length, PROT_READ | PROT_EXEC) == -1 )
        {
            munmap(buffer, length);
            *original_symbol = NULL;
            return -1;
        }
        
        //! thumb
        *original_symbol = (uint8_t*)(buffer + pad) + 1;
        
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
    }
    
    if(align != 0)
    {
        area[0] = T$nop;
    }
    
    thumb[0] = T$bx(A$pc);
    thumb[1] = T$nop;
    
    arm[0] = A$ldr_rd_$rn_im$(A$pc, A$pc, -4);
    arm[1] = (uint32_t)replace;
    
    for(unsigned int offset = 0; offset != blank; ++offset)
    {
        // fill nop
        trail[offset] = T$nop;
    }
    
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
