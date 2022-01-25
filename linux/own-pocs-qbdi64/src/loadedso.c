#include "../inc/loadedso.h"
#include "../inc/util.h"

#define NUM_SO 6

FILE *popen(const char *command, const char *mode);
int pclose(FILE *stream);

const char *so[NUM_SO] = { "libc-dynamic.so","libm-dynamic.so",
                           "libstlport-dynamic.so","libunwind-dynamic.so",
                           "libxed.so","libdynamorio.so" };

bool detectByLoadedSO(){
  FILE *f;
  char buff[MAX_STR];
  int art = 0;

  if ( !(f = fopen("/proc/self/maps", "r")) ){
    perror("fopen");
    return false;
  }

  while(fgets(buff, MAX_STR, f)){
    printd("[loadedso] %s\n", buff);
    for(int l=0; l<NUM_SO; l++){
      if(strstr(buff, so[l]))
        return true;
    }
  }

  return false;
}//detectByLoadedSO
