#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define MAX_MAPS_LEN (1024*1024)

int main(){

  char *start, *eend, *buf, maps_s[MAX_MAPS_LEN];
  uint8_t *p;
  char read_p,write_p,exec_p;
  int found=0;

  FILE *maps = fopen("/proc/self/maps", "r");
  fread(maps_s, 1, MAX_MAPS_LEN, maps);
  buf = maps_s;

  while(sscanf(buf, "%p-%p %c%c%c\n", &start,&eend,&read_p,&write_p,&exec_p) == 5) {

    // Search for at least in +RX 
    if ( read_p == 'r' && exec_p == 'x') {
      uint32_t *ptr = (uint32_t*) start;
      printf("%x\n", *ptr);
    }

    // Line by line
    buf = memchr(buf, '\n', maps_s + MAX_MAPS_LEN-buf);
    buf++;
  }

  return 0;

}
