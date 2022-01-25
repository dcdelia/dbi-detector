#include "../inc/environ.h"

#define NUM_PIN 5
#define NUM_RIO 3

FILE *popen(const char *command, const char *mode);
int pclose(FILE *stream);

const char *pin3envs[NUM_PIN] = { "PIN_CRT_TZDATA","PIN_VM32_LD_LIBRARY_PATH",
                                  "PIN_VM64_LD_LIBRARY_PATH","PIN_INJECTOR32_LD_LIBRARY_PATH",
                                  "PIN_INJECTOR64_LD_LIBRARY_PATH" };
const char *drio8envs[NUM_RIO] = { "DYNAMORIO_CONFIGDIR","DYNAMORIO_TAKEOVER_IN_INIT",
                                   "DYNAMORIO_EXE_PATH" };


bool detectByEnvs(){
  FILE *f;
  char result[MAX_STR];
  int art = 0;


  // PIN
  for (int l=0; l<NUM_PIN; l++ ){
    char cmd[MAX_STR];
    snprintf(cmd, MAX_STR, "grep %s /proc/self/environ", pin3envs[l]);

    f = popen(cmd, "r");
    if (f == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }
    while (fgets(result, sizeof(result), f)) {
        //printf("%s", result);//DEBUG
        ++art;
    }
    pclose(f);
  }

  //DRIO
  for (int l=0; l<NUM_RIO; l++ ){
    char cmd[MAX_STR];
    snprintf(cmd, MAX_STR, "grep %s /proc/self/environ", drio8envs[l]);

    f = popen(cmd, "r");
    if (f == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }
    while (fgets(result, sizeof(result), f)) {
        //printf("%s", result);//DEBUG
        ++art;
    }
    pclose(f);
  }

  if(art){
    return true;
  } else {
    return false;
  }
}//detectByEnvs


bool detectByGetEnv() {
  //PIN
  for (int i=0; i<NUM_PIN; i++) {
    char *value = getenv(pin3envs[i]);
    if (value != NULL) return true;
  }
  //DRIO
  for (int i=0; i<NUM_RIO; i++) {
    char *value = getenv(drio8envs[i]);
    if (value != NULL) return true;
  }

  return false;
}//detectByGetEnv
