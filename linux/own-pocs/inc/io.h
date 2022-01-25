#ifndef IO_H
#define IO_H

#include "../inc/common.h"
/*
  https://man7.org/linux/man-pages/man5/proc.5.html

  rchar: characters read
  wchar: characters written
  syscr: read syscalls
  syscw: write syscalls
  read_bytes: bytes read
  write_bytes: bytes written
  cancelled_write_bytes: zero writeout
*/
bool detectByIO();

#endif //IO_H
