//usr/bin/gcc -O2 demo.c -o demo -static; exec ./demo

#include "tuxthread.h"
#include <stdio.h>
#include <string.h>


int thread_func(void *thread_arg) {
  char *string = (char *)thread_arg;
  printf("thread_func got passed argument: %s\n", string);
  strcpy(string, "bar");
  return 42;
}

int main() {

  char thread_arg[] = "foo";
  thrd_t thread;
  thrd_create(&thread, thread_func, thread_arg);

  int result;
  thrd_join(thread, &result);
  printf("buffer: %s result: %d\n", thread_arg, result);
  return 0;
}
