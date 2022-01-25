#include "../inc/mmap.h"
#include "../inc/util.h"
#include <stdbool.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define DRIO_START 0x71000000 // Drio8 start memory mapping

/*
    /proc/[pid]/statm
    Provides information about memory usage, measured in pages.

    DRIO and PIN increase the vm size
    
    ~33000+ small binaries
    ~1000000+ telegram

    Set to your expected VmSize (pages) and test at startup
*/
#define MAX_VSIZE 1000

bool detectByVmSize(){

    FILE *f;
    char buff[MAX_BUFF];
    char *str;
    int val;

    if ( !(f = fopen("/proc/self/statm", "r")) ){
      perror("fopen");
      return false;
    }

    if (!fgets(buff, MAX_BUFF, f)){
      return false;
      fclose(f);
    }
    fclose(f);

    /* Removing trailing new line */
    unsigned buffLen = strlen(buff);
    if (buff[buffLen - 1] == '\n') {
        buff[buffLen - 1] = '\0';
    }
    /* Get value */
    str = strtok(buff, " ");
    val = atoi(str);
    printd("[VmSize] %s -- %s -- %d\n", buff,str,val); //DEBUG


    if (val > MAX_VSIZE)
      return true;

    return false;
}//detectByVmSize


/*
    Try to alloc memory where DRIO setups its SO in 64bit PIEs
    See MAP_FIXED_NOREPLACE
    https://man7.org/linux/man-pages/man2/mmap.2.html
 */
bool detectByAllocMem(){
  int *addr;
  if( (addr = mmap((void *)DRIO_START, 4096,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                      -1, 0)) == MAP_FAILED ) return true;

//  if (addr != (int *)DRIO_START)
//    return true;

  return false;
}//detectByAllocMem


bool detectByCodeLoc(){

  /*
    /proc/[pid]/stat

    (26) startcode  %lu  [PT]
    The address above which program text can run.

    (27) endcode  %lu  [PT]
    The address below which program text can run.

    Check if the program code is loaded where expected
  */

  FILE *f;
  char c;
  int count=0;
  unsigned off;
  char buff[MAX_BUFF];
  char *pAbove, *pBelow;
  unsigned long vAbove, vBelow;
  unsigned long rip=0;

  if ( !(f = fopen("/proc/self/stat", "r")) ){
    perror("fopen");
    return false;
  }

  if (!fgets(buff, MAX_BUFF, f)){
    return false;
    fclose(f);
  }
  fclose(f);

  /* Removing trailing new line */
  unsigned buffLen = strlen(buff);
  if (buff[buffLen - 1] == '\n') {
    buff[buffLen - 1] = '\0';
  }
  //printf("%s\n", buff);//DEBUG

  for(off=0; off<buffLen; off++){
    if (buff[off] == ' ')
      count++;
    if(count == 25){
      off++;
      break;
    }
  }//for

  pAbove = strtok(&buff[off], " ");
  vAbove = atoll(pAbove);
  printd("[codeloc] startcode --> %p\n", (void*)vAbove);//DEBUG
  pBelow = strtok(NULL, " ");
  vBelow = atol(pBelow);
  printd("[codeloc] endcode --> %p\n", (void*)vBelow);//DEBUG


#ifdef BUILD_64 //64bit
  asm volatile(
                "leaq (%%rip), %0\n\t"
                : "=r"(rip)
              );
#else
  asm volatile(
                "1: lea 1b, %0;"
                : "=r"(rip)
              );
#endif

  assert(rip);
  printd("[codeloc] rip = %p\n", (void*)rip);//DEBUG

  if ( rip > vAbove && rip < vBelow){
    return false; /* As should be */
  }else{
    return true;
  }

}//detectByCodeLoc


/*
  Adapted from
  https://github.com/kirschju/debugmenot/blob/master/src/test_nearheap.c

  Drio relocates the heap near to the end of the bss section
*/
bool detectByHeapLoc(){
    static unsigned char bss;
    unsigned char *probe = malloc(0x10);

  printd("[heaploc] %p - %p : %x\n", probe, &bss, (int)(probe-&bss));//DEBUG

    if (probe - &bss > 0x20000)
      return false;

    return true;
}//detectByHeapLoc


void testSignature(){
#ifdef __i386__
  asm inline(
    "nop;"        // 90
    "nop;"        // 90
    "push %eax;"  // 50
    "pop %eax;"   // 58
  );
#else
  asm inline(
    "nop;"        // 90
    "nop;"        // 90
    "push %rax;"  // 50
    "pop %rax;"   // 58
  );
#endif //__i386__
}//testSignature


char msg[] = "DS var\n";

bool detectByCodeSignature(){

  char *start, *eend, *buf, maps_s[MAX_MAPS_LEN];
  uint8_t *p;
  char read_p,write_p,exec_p;
  int found=0;

  testSignature();

  FILE *maps = fopen("/proc/self/maps", "r");
  fread(maps_s, 1, MAX_MAPS_LEN, maps);
  buf = maps_s;

  while(sscanf(buf, "%p-%p %c%c%c\n", &start,&eend,&read_p,&write_p,&exec_p) == 5) {

    // Search for at least in +RX 
    if ( read_p == 'r' && exec_p == 'x') {
      //printf("%p - %p %c%c%c\n", start, eend, read_p,write_p,exec_p);
      
      if (found > 1) return true;

      for (p = start; p < (uint8_t*)eend-4; p++) {
        if (
          *p == 0x90 &&
          *(p+1) == 0x90 &&
          *(p+2) == 0x50 &&
          *(p+3) == 0x58
        ){
          //printf("found at %p\n", p);
          found++;
          p++;
          break;    
        }
      }
    }

    // Line by line
    buf = memchr(buf, '\n', maps_s + MAX_MAPS_LEN-buf);
    buf++;
  }

  return false;

}//detectByCodeSignature


