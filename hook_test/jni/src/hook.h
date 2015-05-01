#ifndef __HOOK_H__
#define __HOOK_H__

#include <dlfcn.h>
#include <stdlib.h>
#include <errno.h>

int hook_function( void* symbol, void* replace, void** original_symbol, size_t* bytes_used );
int unhook_function( void* symbol, void* original_symbol, size_t bytes_used);

#endif