typedef int pid_t;
typedef long off_t;
typedef unsigned long size_t;

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

#define TUXTHREAD_STACK_SIZE 1024 * 1024 * 4

#define WEXITSTATUS(s) (((s)&0xff00) >> 8)

// syscall rdi rsi rdx r10 r8 r9
// func    rdi rsi rdx rcx r8 r9

//#define _GNU_SOURCE
//#include <sched.h>

__attribute__((naked)) int clone(int (*fn)(void *), void *restrict stack,
                                 int flags, void *restrict arg) {
  __asm__("mov    %rdi,%r9\n"  // move func pointer for later use
          "mov    %rcx,%r12\n" // move arg pointer for later

          "mov    $0x38,%eax\n" // clone syscall
          "mov    %rdx,%rdi\n"  // pass flags to syscall
                                // %rsi is stack
          "mov 	$0,%rdx\n"
          "mov 	$0,%r10\n"
          "mov 	$0,%r8\n"
          "syscall \n"

          "test   %eax,%eax\n" // test return of syscall
          "jne    .foo\n"      // skip to end
          "mov    %r12,%rdi\n" // getting args back to call func
          "callq  *%r9\n"      // call func

          // exit with return value of func
          "mov    %rax,%rdi\n"
          "mov    $0x3c,%rax\n"
          "syscall \n"
          ".foo:"
          "retq   \n");
}

static void *mmap(void *addr, size_t len, int prot, int flags, int fd,
                  off_t off) {
  register int r10 asm("r10") = flags;
  register int r8 asm("r8") = fd;
  register off_t r9 asm("r9") = off;

  void *result;
  asm volatile("syscall"
               : "=a"(result)
               : "0"(9), "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8),
                 "r"(r9)
               : "rcx", "r11", "memory");
  return result;
}

static int munmap(void *addr, size_t len) {
  int result;
  asm volatile("syscall"
               : "=a"(result)
               : "0"(9), "D"(addr), "S"(len)
               : "rcx", "r11", "memory");
  return result;
}

static pid_t waitpid(pid_t pid, int *status, int options) {
  size_t result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "0"(61), "D"(pid), "S"(status), "d"(options)
                   : "rcx", "r11", "memory");
  return result;
}
/*
pid_t fork(){
  register long r10 asm("r10") = 0;
  register long r8 asm("r8") = 0;
  register long r9 asm("r9") = 0;

  long flags = CLONE_CHILD_CLEARTID |CLONE_CHILD_CLEARTID | SIGCHLD;

  pid_t result;
  asm volatile("syscall"
               : "=a"(result)
               : "0"(0x38), "D"(flags), "S"(0), "d"(0), "r"(r10), "r"(r8),
                 "r"(r9)
               : "rcx", "r11", "memory");
  return result;
}
*/
typedef struct {
  pid_t pid;
  char *stack;
} thrd_t;

void thrd_yield() {
  asm volatile("syscall" : : "a"(24) : "rcx", "r11", "memory");
}

int thrd_create(thrd_t *thr, int (*func)(void *), void *arg) {
  unsigned flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                   CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;

  char *stack = mmap(0, TUXTHREAD_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  thr->pid = clone(func, stack + TUXTHREAD_STACK_SIZE - 1, flags, arg);
  thr->stack = stack;
  return 0;
}

int thrd_join(thrd_t thr, int *result) {
  waitpid(thr.pid, result, 0);
  munmap(thr.stack, TUXTHREAD_STACK_SIZE);
  *result = WEXITSTATUS(*result);
  return 0;
}

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static int futex(volatile void *addr1, int op, int val1, void *timeout,
                 void *addr2, int val3) {
  register void *r10 asm("r10") = timeout;
  register void *r8 asm("r8") = addr2;
  register int r9 asm("r9") = val3;

  int result;
  asm volatile("syscall"
               : "=a"(result)
               : "0"(202), "D"(addr1), "S"(op), "d"(val1), "r"(r10), "r"(r8),
                 "r"(r9)
               : "rcx", "r11", "memory");
  return result;
}
/*
// from linux source code
static inline unsigned int xchg(volatile unsigned int *ptr, unsigned int x) {
        asm volatile("xchgl %0,%1"
                : "=r" (x), "+m" (*ptr)
                : "0" (x)
                : "memory");
    return x;
}*/
#define xchg(a, b) __atomic_exchange_n(a, b, __ATOMIC_SEQ_CST)
#define cmpxchg(P, O, N) __sync_val_compare_and_swap((P), (O), (N))

typedef volatile _Atomic(unsigned int) mtx_t;

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
    futex(mutex, FUTEX_WAIT, CONTENDED, 0, 0, 0);
    c = xchg(mutex, CONTENDED);
  }
  return 0;
}

int mtx_unlock(mtx_t *mutex) {
  int c = xchg(mutex, UNLOCKED);
  if (c == CONTENDED) {
    // wake up one waiter
    futex(mutex, FUTEX_WAKE, 1, 0, 0, 0);
  }
  return 0;
}
