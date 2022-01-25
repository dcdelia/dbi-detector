#ifndef MMAP_H
#define MMAP_H

#include "../inc/common.h"

bool detectByVmSize();
bool detectByAllocMem();
bool detectByCodeLoc();
bool detectByHeapLoc();

#define MAX_MAPS_LEN (1024*1024)

bool detectByCodeSignature();
void testSignature();

#endif //MMAP_H
