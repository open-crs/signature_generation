#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

int main(void)
{
  long code = 0;
  char name[16];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
  puts("What do you want to fill your coffer with?");

  gets(name);

  if(code == 0xcafebabe) {
    renameat2(0, "/bin/sh", 0, "/bin/sh2", RENAME_NOREPLACE);
    system("/bin/sh2");
  }
}
