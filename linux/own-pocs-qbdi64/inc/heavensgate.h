#ifndef REF_H
#define REF_H

#include "../inc/common.h"

#define SYSCNO_GETSID 0x93
typedef unsigned long long u64;
typedef unsigned u32;

#ifdef __i386__
extern void __block_32(u64 *cs) __attribute__((cdecl));
bool ctx_32to64();
#else
bool ctx_64to32();
#endif

#endif //REF_H
