#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <setjmp.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#if defined(__LP64__) || defined(_LP64)
#define BUILD_64   1
#endif


#define MAX_PATH 1000
#define MAX_STR 1000
#define MAX_PID 8
#define MAX_BUFF 500
#define SIZE_PAGE 0x1000

typedef long long unsigned int uint64;
//typedef int bool;
//enum { False, True };  // Define boolean type

#endif //COMMON_H
