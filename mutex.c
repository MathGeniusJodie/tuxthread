//usr/bin/gcc -O2 mutex.c -o mutex -static -pedantic; exec ./mutex

#include <unistd.h>
#include <string.h>
#include "tuxthread.h"

mtx_t printf_mutex;


int thread_func(void *thread_arg) {

  mtx_lock(&printf_mutex);
  write(1,"1\n",2);
  sleep(1);
  write(1,"2\n",2);
  sleep(1);
  write(1,"3\n",2);
  sleep(1);
  write(1,"4\n",2);
  sleep(1);
  write(1,"5\n",2);
  sleep(1);
  write(1,"6\n",2);
  mtx_unlock(&printf_mutex);

  return 0;
}

int main() {
  mtx_init(&printf_mutex,0);

  thrd_t thread0;
  thrd_create(&thread0, thread_func, 0);
  thrd_t thread1;
  thrd_create(&thread1, thread_func, 0);
  thrd_t thread2;
  thrd_create(&thread1, thread_func, 0);

  int result;
  thrd_join(thread0, &result);
  thrd_join(thread1, &result);
  thrd_join(thread2, &result);
  
  return 0;
}
