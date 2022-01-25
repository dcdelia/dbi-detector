#include "../inc/signal.h"
#include "../inc/util.h"

/*
  SigCgt: Masks (expressed in hexadecimal)
  indicating signals being caught

  Pin fffffffff780feff
  -->   uncaught
  9) SIGKILL
  17) SIGCHLD     18) SIGCONT     19) SIGSTOP     20) SIGTSTP
  21) SIGTTIN     22) SIGTTOU     23) SIGURG
  28) SIGWINCH

  Drio ffffffffffc1feff
  -->   uncaught
  9) SIGKILL
  18) SIGCONT     19) SIGSTOP     20) SIGTSTP
  21) SIGTTIN     22) SIGTTOU
*/

#define PIN_SigCgt "fffffffff780feff"
#define DRIO_SigCgt "ffffffffffc1feff"


bool detectBySigCgt(){

  FILE *f;
  char buff[MAX_BUFF];
  char *str;

  if ( !(f = fopen("/proc/self/status", "r")) ){
    perror("fopen");
    return true; //to do
  }

  while ( fgets(buff, MAX_BUFF, f) != NULL){

    /* Removing trailing new line */
    unsigned buffLen = strlen(buff);
    if (buff[buffLen - 1] == '\n') {
        buff[buffLen - 1] = '\0';
    }
    /* Get value */
    if (!strncmp(buff, "SigCgt", 6)){
      str = strtok(buff, "\t");
      str = strtok(NULL, "\0");
      printd("[SigCgt] buff = %s, str = %s\n", buff,str);//DEBUG

      if (!strncmp(str, PIN_SigCgt, 16) || !strncmp(str, DRIO_SigCgt, 16))
        return true;
    }
  }
  fclose(f);

  return false;

}//detectBySigCgt