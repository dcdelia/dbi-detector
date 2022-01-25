#include "../inc/loadedso.h"
#include "../inc/environ.h"
#include "../inc/io.h"
#include "../inc/mmap.h"
#include "../inc/signal.h"
#include "../inc/heavensgate.h"
#include "../inc/perm.h"

#include <sys/ptrace.h>

/* Enable for sleeping  */
//#define SLEEP

int main(int argc, char const *argv[], char *envp[]) {

#ifdef SLEEP
  printf("PID: %d, PPID: %d\n", getpid(), getppid());
  for(;;)
    pause();
  return 0;
#endif

  /* Exec before doing anything */
  printf("%s by IO\n", detectByIO() ? "[+] Detected" : "[-] Not detected");
  printf("%s by SigCgt\n", detectBySigCgt() ? "[+] Detected" : "[-] Not detected");
  printf("%s by VmSize\n", detectByVmSize() ? "[+] Detected" : "[-] Not detected");
  printf("%s by loadedso\n", detectByLoadedSO() ? "[+] Detected" : "[-] Not detected");
  //printf("%s by envs\n", detectByEnvs() || detectByGetEnv() ? "[+] Detected" : "[-] Not detected"); // Dyninst crashes
  printf("%s by codeloc\n", detectByCodeLoc() ? "[+] Detected" : "[-] Not detected");
  printf("%s by PagePerm\n", detectByPagePerm() ? "[+] Detected" : "[-] Not detected");
  printf("%s by PagePerm2\n", detectByPagePerm2() ? "[+] Detected" : "[-] Not detected");
  printf("%s by heaploc\n", detectByHeapLoc() ? "[+] Detected" : "[-] Not detected");
  printf("%s by CodeSignature\n", detectByCodeSignature() ? "[+] Detected" : "[-] Not detected");
#ifdef __i386__
  printf("%s by ctx switch\n", ctx_32to64() ? "[+] Detected" : "[-] Not detected");
#else
  printf("%s by PagePerm3\n", detectByPagePerm3() ? "[+] Detected" : "[-] Not detected");
  printf("%s by ctx switch\n", ctx_64to32() ? "[+] Detected" : "[-] Not detected");
  printf("%s by alloc\n", detectByAllocMem() ? "[+] Detected" : "[-] Not detected");
#endif //__i386__

  printf("Testing ended.\n");
  sleep(30);
  printf("PUH\n");

  return 0;
}
