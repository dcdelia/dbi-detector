#include "../inc/perm.h"

//#define DEBUG
#define LEN (1024 * 1024)

static jmp_buf jmpBuff;
static int volatile flag;

static void handler(int sig, siginfo_t *si, void *unused)
{
#ifdef DEBUG    
    printf("Got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
#endif //DEBUG    
    flag = 0;             //not detected
    longjmp(jmpBuff, 10); //come back where setjmp left
}



  bool detectByPagePerm(){
  flag = 1;
  char *addr;
  struct sigaction sa, old;
  bzero(jmpBuff, sizeof(jmpBuff));

  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1)
    perror("sigaction");


  /* Try executing without PROT_EXEC permission */
  addr = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED)
    perror("mmap");

  addr[0] = 0xc3;

  /* Save context */
  if (setjmp(jmpBuff))
    goto jump;

  ((void(*)())addr)();

jump:
    //printf("After 1\n" );//DEBUG

    if(flag)
      return true;

    return false;

}//detectByPagePerm


char data_var=0xc3; // Initialized variable in .data

bool detectByPagePerm2(){
  flag = 1;
  struct sigaction sa, old;
  bzero(jmpBuff, sizeof(jmpBuff));

  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  // if (sigaction(SIGSEGV, &sa, NULL) == -1)
  //   perror("sigaction");

  /* Save context */
  if (setjmp(jmpBuff))
    goto jump;

  /* Try executing in .data section with RW perms */
  ((void(*)())&data_var)();

jump:
    //printf("After 2\n" );//DEBUG

    if(flag)
      return true;

    return false;

}//detectByPagePerm2



bool detectByPagePerm3(){
#ifdef BUILD_64    
    flag = 1;
    struct sigaction sa, old;
    bzero(jmpBuff, sizeof(jmpBuff));

    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
       perror("sigaction");
  
    char * buff = mmap(NULL, 2*SIZE_PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buff == MAP_FAILED)
        perror("mmap");
#ifdef DEBUG  
    printf("Allocated two RWX pages at %p\n", buff);
#endif //DEBUG      

    int cnt = 0;
    char *start, *pagebreak, *end ;

    asm volatile(
        "leaq 0x2(%%rip), %0;"  // 0:   48 8d 15 02 00 00 00    mov start,%rdx
        "jmp 2f;"               // 7:   eb 0b                   jmp 2f
    //start
        "cmp $0, %1;"           // 9:   83 f8 00                cmp $0x0,cnt
        "je 1f;"                // c:   74 01                   je pb
        "nop;"                  // e:   90                      nop
    "1:"//pb
        "nop;"                  // f:   90                      nop
        "incl %1;"              // 10:  ff c0                   inc cnt
        "ret;"                  // 12:  c3                      retq
    "2:"//end                   // 13:
        :"=r"(start), "=r"(cnt)
        : "r"(cnt)
        :
    );

    pagebreak = start +0x6;
    end = start +0xb;   
    char *dest = buff + SIZE_PAGE - (pagebreak - start);
#ifdef DEBUG      
    printf("start=%p, end=%p, pagebreak=0x%p\n", start, end, pagebreak);
    printf("buff=%p, dest=%p, pagebreak=0x%p\n", buff, dest, pagebreak);
    
    /* 
        ------------------------ buff
                   
                   +RWX                             <-- start = dest
        ------------------------ buff + SIZE_PAGE   <-- pagebreak
                   +W                               <-- end

        ------------------------ buff + 2*SIZE_PAGE
    */

    printf("Placing test code at %p-%p\n", (void *) dest, (void *) (dest + (end - start)));
#endif //DEBUG

    memcpy((void *)dest, (void *)start, end - start);

#ifdef DEBUG    
    printf("Adding PROT_WRITE protection to %p\n", (void *)(buff + SIZE_PAGE));
    getchar();
#endif //DEBUG
    if ( mprotect(buff + SIZE_PAGE, SIZE_PAGE, PROT_WRITE) == -1)
        perror("mprotect");
    
    /* Save context */
    if (setjmp(jmpBuff))
        goto jump;

    ((void(*)())dest)();
	//printf("Test code executed\n");



jump:
    //printf("After 3\n" );//DEBUG

    if(flag)
      return true;
#endif //BUILD_64
    return false;

}//detectByPagePerm2