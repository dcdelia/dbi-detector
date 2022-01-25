#include "../inc/io.h"
#include "../inc/util.h"

/*
    DRIO and PIN increase chars read
    Set to your expected read chars

    ~492172+ telegram
 */
#define MAX_RCHAR 6000

bool detectByIO(){
  FILE *f;
  char buff[MAX_BUFF];
  char *str;
  int val;

  if ( !(f = fopen("/proc/self/io", "r")) ){
    perror("fopen");
    return False;
  }

  if (fgets(buff, MAX_BUFF, f) == NULL){
    perror("fgets");
    return False;
  }

  /* Removing trailing new line */
  unsigned buffLen = strlen(buff);
  if (buff[buffLen - 1] == '\n') {
    buff[buffLen - 1] = '\0';
  }
  /* Get value */
  str = strtok(buff, ": ");
  str = strtok(NULL, "\0");
  val = atoi(str);

  printd("[IO] %s -- %s -- %d\n", buff,str,val); //DEBUG

  if (val > MAX_RCHAR)
    return True;

  return False;
}//detectByIO
