# Exploit detection using system calls tracing

## Kernel space

### run kernel module

```console
foo@bar:~/syscall_hooking$ cd kernel-space 
foo@bar:~/syscall_hooking/kernel-space$ make
foo@bar:~/syscall_hooking/kernel-space$ sudo insmod hooking.ko
```

## User space

### run python script

```console
foo@bar:~/syscall_hooking$ cd user-space
foo@bar:~/syscall_hooking/user-space$ sudo python3 main.py
```