#define TUXTHREAD_STACK_SIZE (1024 * 128)

typedef int pid_t;
typedef long off_t;
typedef unsigned long size_t;

// syscall rdi rsi rdx r10 r8 r9
// func    rdi rsi rdx rcx r8 r9

// rbx,rsp,rbp,r12,r13,r14,r15 need to be preserved

//#define _GNU_SOURCE
//#include <sched.h>
//#define tt_clone clone
// https://man7.org/linux/man-pages/man2/clone.2.html

// syscall rdi rsi rdx r10 r8 r9
// func    rdi rsi rdx rcx r8 r9

static int tt_clone(int (*fn)(void *), void *child_stack, int flags, void *arg){
          //int *parent_tid, void *new_tls, int *child_tid) {
  int res;
  __asm__ volatile(
	  "and    $-16,%2\n" // align to 16 bits
      // push onto child_stack
      "subq   $16, %2\n"
      "movq   %4, 8(%2)\n" // args
      "movq   %3, 0(%2)\n" // fn

      "movq   $56, %%rax\n"
      //"movq   %6, %%r8\n"  // new_tls
      //"movq   %7, %%r10\n" // child_tid
      "syscall\n"
      // if (rax != 0) return
      "testq  %%rax, %%rax\n"
      "jnz    1f\n"
      // in child now
      "xorq   %%rbp, %%rbp\n" // for debug
      // call fn(arg)
      "popq   %%rax\n"
      "popq   %%rdi\n"
      "call   *%%rax\n"
      // call exit
      "movq   %%rax, %%rdi\n"
      "movq   $60, %%rax\n"
      "syscall\n"
      // return to parent
      "1:\n"
      : "=a"(res)
      : "D"((long)flags), // 1 rdi
        "S"(child_stack), // 2 rsi
        "r"(fn),          // 3
        "r"(arg)//,       // 4
        //"d"(parent_tid),  // 5 rdx
        //"r"(new_tls),     // 6
       // "r"(child_tid)    // 7
      : "memory",// "r8", "r10",
      "r11", "rcx");
  return res;
}

#if defined(__GNUC__) || defined(__clang__)

static void *tt_mmap(void *addr, size_t len, int prot, int flags, int fd,
                     off_t off) {
  register int r10 __asm__("r10") = flags;
  register int r8 __asm__("r8") = fd;
  register off_t r9 __asm__("r9") = off;

  void *result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "0"(9), "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8),
                     "r"(r9)
                   : "rcx", "r11", "memory");
  return result;
}

static int tt_futex(volatile void *addr1, int op, int val1, void *timeout,
                    void *addr2, int val3) {
  register void *r10 __asm__("r10") = timeout;
  register void *r8 __asm__("r8") = addr2;
  register int r9 __asm__("r9") = val3;

  int result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "0"(202), "D"(addr1), "S"(op), "d"(val1), "r"(r10),
                     "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return result;
}
#else

__asm__(".text\n"
        "tt_mmap:\n"
        "	mov $9,%rax\n"
        "	mov %rcx,%r10\n"
        "	syscall\n"
        "	ret\n");

void *tt_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);

__asm__(".text\n"
        "tt_futex:\n"
        "	mov $202,%rax\n"
        "	mov %rcx,%r10\n"
        "	syscall\n"
        "	ret\n");

int tt_futex(volatile void *addr1, int op, int val1, void *timeout, void *addr2,
             int val3);
#endif

#define mtx_plain 0
#define SIGCHLD 17
#define CSIGNAL 0x000000ff
#define CLONE_VM 0x00000100
#define CLONE_FS 0x00000200
#define CLONE_FILES 0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_PTRACE 0x00002000
#define CLONE_VFORK 0x00004000
#define CLONE_PARENT 0x00008000
#define CLONE_THREAD 0x00010000
#define CLONE_NEWNS 0x00020000
#define CLONE_SYSVSEM 0x00040000
#define CLONE_SETTLS 0x00080000
#define CLONE_PARENT_SETTID 0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED 0x00400000
#define CLONE_UNTRACED 0x00800000
#define CLONE_CHILD_SETTID 0x01000000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000
#define CLONE_IO 0x80000000

#define MAP_GROWSDOWN 0x0100
#define MAP_ANONYMOUS 0x0020
#define MAP_PRIVATE 0x0002
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define WNOHANG 1
#define WUNTRACED 2

#define WSTOPPED 2
#define WEXITED 4
#define WCONTINUED 8
#define WNOWAIT 0x1000000

#define WEXITSTATUS(s) (((s)&0xff00) >> 8)
#define WTERMSIG(s) ((s)&0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WCOREDUMP(s) ((s)&0x80)
#define WIFEXITED(s) (!WTERMSIG(s))
#define WIFSTOPPED(s) ((short)((((s)&0xffff) * 0x10001) >> 8) > 0x7f00)
#define WIFSIGNALED(s) (((s)&0xffff) - 1U < 0xffu)
#define WIFCONTINUED(s) ((s) == 0xffff)

static int tt_munmap(void *addr, size_t len) {
  int result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "0"(9), "D"(addr), "S"(len)
                   : "rcx", "r11", "memory");
  return result;
}

static pid_t tt_waitpid(pid_t pid, int *status, int options) {
  size_t result;
  __asm__ volatile("xor %%r10,%%r10\n"
                   "syscall"
                   : "=a"(result)
                   : "0"(61), "D"(pid), "S"(status), "d"(options)
                   : "rcx", "r11", "r10", "memory");
  return result;
}
/*
pid_t fork(){
  register long r10 asm("r10") = 0;
  register long r8 asm("r8") = 0;
  register long r9 asm("r9") = 0;

  long flags = CLONE_CHILD_CLEARTID |CLONE_CHILD_CLEARTID | SIGCHLD;

  pid_t result;
  __asm__ volatile("syscall"
               : "=a"(result)
               : "0"(0x38), "D"(flags), "S"(0), "d"(0), "r"(r10), "r"(r8),
                 "r"(r9)
               : "rcx", "r11", "memory");
  return result;
}
*/
typedef struct {
  char *stack;
  pid_t pid;
} thrd_t;

void thrd_yield() {
  __asm__ volatile("syscall" : : "a"(24) : "rcx", "r11", "memory");
}

int thrd_create(thrd_t *thr, int (*func)(void *), void *arg) {
  unsigned flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                   CLONE_SYSVSEM;

  char *stack = tt_mmap(0, TUXTHREAD_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  thr->pid = tt_clone(func, stack + TUXTHREAD_STACK_SIZE - 1, flags, arg);
                      //0, 0, 0);
  thr->stack = stack;
  return 0;
}

int thrd_join(thrd_t thr, int *result) {
  tt_waitpid(thr.pid, result, 0);
  tt_munmap(thr.stack, TUXTHREAD_STACK_SIZE);
  *result = WEXITSTATUS(*result);
  return 0;
}

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

// from linux source code
static inline unsigned int xchg(volatile unsigned int *ptr, unsigned int x) {
  __asm__ volatile("xchgl %0,%1" : "=r"(x), "+m"(*ptr) : "0"(x) : "memory");
  return x;
}

static inline unsigned int cmpxchg(volatile unsigned int *ptr, unsigned int old,
                                   unsigned int new) {
  int ret;
  __asm__ volatile("lock cmpxchgl %2,%1"
                   : "=a"(ret), "+m"(*ptr)
                   : "r"(new), "0"(old)
                   : "memory");
  return ret;
}

static inline unsigned int xadd(volatile unsigned int *ptr, unsigned int x) {
  __asm__ volatile ("lock xaddl %0, %1\n"
  				    : "+r" (x), "+m" (*ptr)
  				    : : "memory", "cc");	
  return x;
}

//#define xchg(a, b) __atomic_exchange_n(a, b, __ATOMIC_SEQ_CST)
//#define cmpxchg(P, O, N) __sync_val_compare_and_swap((P), (O), (N))

// typedef volatile _Atomic(unsigned int) mtx_t;
typedef volatile unsigned int mtx_t;

enum mtx_state { UNLOCKED, LOCKED, CONTENDED };

int mtx_init(mtx_t *mutex, int type) {
  *mutex = UNLOCKED;
  return 0;
}

int mtx_lock(mtx_t *mutex) {
  int c = cmpxchg(mutex, UNLOCKED, LOCKED);
  if (c == UNLOCKED)
    return 0;

  cmpxchg(mutex, LOCKED, CONTENDED);
  while (c) { // protect against spurious wakeups
    // wait until not CONTENDED
    tt_futex(mutex, FUTEX_WAIT, CONTENDED, 0, 0, 0);
    c = xchg(mutex, CONTENDED);
  }
  return 0;
}

int mtx_unlock(mtx_t *mutex) {
  int c = xchg(mutex, UNLOCKED);
  if (c == CONTENDED) {
    // wake up one waiter
    tt_futex(mutex, FUTEX_WAKE, 1, 0, 0, 0);
  }
  return 0;
}
/*
typedef struct {
    mtx_t *m;
    unsigned int seq;
} cnd_t;

int cnd_init(cnd_t *cond) {
    cond->m = 0;
    cond->seq = 0;
    return 0;
}

int cnd_signal(cnd_t *cond) {
    xadd(&cond->seq, 1);
    tt_futex(&cond->seq, FUTEX_WAKE, 1, 0, 0, 0);
    return 0;
}

int cnd_wait(cnd_t *cond, mtx_t *mutex) {
    int seq = cond->seq;
    if (cond->m != mutex) {
        if (cond->m)
            return -1;
        cmpxchg(&cond->m, 0, mutex);
        if (cond->m != mutex)
            return -1;
    }
    mtx_unlock(mutex);
    tt_futex(&cond->seq, FUTEX_WAIT, seq, 0, 0, 0);
    while (xchg(mutex, CONTENDED))
        tt_futex(mutex, FUTEX_WAIT, CONTENDED, 0, 0, 0);
    return 0;
}
*/
