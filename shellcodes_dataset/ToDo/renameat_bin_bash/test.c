// Disassembly of section .text:

// 0000000000000000 <foo>:
//    0:	f3 0f 1e fa          	endbr64 
//    4:	41 b8 01 00 00 00    	mov    r8d,0x1
//    a:	31 d2                	xor    edx,edx
//    c:	31 ff                	xor    edi,edi
//    e:	31 c0                	xor    eax,eax
//   10:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # 17 <foo+0x17>
//   17:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 1e <foo+0x1e>
//   1e:	e9 00 00 00 00       	jmp    23 <.LC1+0x15>
 
int main(void)
{
    char shellcode[] = "";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}

