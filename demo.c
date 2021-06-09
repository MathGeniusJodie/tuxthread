//usr/bin/gcc -O2 demo.c -o demo -static; exec ./demo

#include "tuxthread.h"
#include <stdio.h>
#include <string.h>

mtx_t printf_mutex;


int thread_func(void *thread_arg) {
  char *string = (char *)thread_arg;
  mtx_lock(&printf_mutex);
  printf("thread_func got passed argument: %s\n", string);
  mtx_unlock(&printf_mutex);
  strcpy(string, "bar");
  return 42;
}

int main() {
  mtx_init(&printf_mutex,0);

  char thread_arg[] = "foo";
  thrd_t thread;
  thrd_create(&thread, thread_func, thread_arg);

  int result;
  thrd_join(thread, &result);
  mtx_lock(&printf_mutex);
  printf("buffer: %s result: %d\n", thread_arg, result);
  mtx_unlock(&printf_mutex);
  return 0;
}
