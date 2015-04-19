#ifndef _UTIL_H_
#define _UTIL_H_

#include <unistd.h>
#include <dirent.h> 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

extern "C"{
int find_pid_of(const char* process_name);
}

#endif