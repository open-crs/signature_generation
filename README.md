# Exploit detection using system calls tracing

## Kernel space

### run kernel module

```console
foo@bar:~/syscall_hooking$ cd ./dev/kernel-space 
foo@bar:~/syscall_hooking/dev/kernel-space$ make
foo@bar:~/syscall_hooking/dev/kernel-space$ sudo insmod hooking.ko
```

## User space

### run python script

```console
foo@bar:~/syscall_hooking$ cd ./dev/user-space
foo@bar:~/syscall_hooking/dev/user-space$ sudo python3 main.py
```