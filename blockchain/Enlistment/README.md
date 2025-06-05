# Enlistment

10<sup>th</sup> May 2025 \
Prepared By: perrythepwner \
Challenge Author(s): **perrythepwner** \
Difficulty: <font color=light-green>Very-Easy</font>

---

# TLDR
The challenge aims to be a setup challenge for blockchain challenges. To solve it a player must read the `privateKey` private variable via low level storage access and compute the expected `_proofHash` used by the target contract. 

# Description
Task Force Phoenix is mobilizing to counter the growing cyber threat of Operation Blackout. Applications are now open for enlistment in the Blockchain Security Unit.
I've heard that you are a good one Agent P. huh? I don't like to talk much but to me it looks like one of those once-in-a-lifetime opportunities...

# Skills Required
- Basic understanding of Solidity and smart contracts

# Skills Learned
- Smart contracts interaction
- Solidity lang basics: `private`, `immutable`, primitive types, `keccak256`
- EVM storage basics

# Challenge Scenario
We're given some attachments and two ports to interact to.  
By simply interacting to the given `ip:port` pairs, we understand that:  
    - one is a TCP connection   
    - the other is an HTTP webserver that replies with "rpc is running!"  
Connecting to the TCP port using netcat we receive connection information needed to interact with the challenge environment. Selecting the `1 - Get connection informations` option we will get the player private key, player address, target contract address and finally a "setup" contract address.    
The HTTP port is a JSON-RPC endpoint that allows us to interact with the challenge local blockchain instance.

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import { Enlistment } from "./Enlistment.sol";

contract Setup {
    Enlistment public TARGET;
    address public player;

    event DeployedTarget(address at);

    constructor(address _player, bytes32 _key) {
        TARGET = new Enlistment(_key);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.enlisted(player); 
    }
}
```

Having a `Setup.sol` contract in blockchain challenges is a common pattern. This smart contract is usually needed for:  
    1) deploying the target contract (the actual challenge)  
    2) providing a checker as an external function to verify solve requirements are met  
In this case, the `Setup` contract deploys the `Enlistment` contract and provides the `isSolved()` function to check if the player is "enlisted". In that case, the player address is just the same address passed earlier in the TCP connection when the instance was started.

## `Enlistment.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

contract Enlistment {
    bytes16 public publicKey;
    bytes16 private privateKey;
    mapping(address => bool) public enlisted;
    
    constructor(bytes32 _key) {
        publicKey = bytes16(_key);
        privateKey = bytes16(_key << (16*8));
    }

    function enlist(bytes32 _proofHash) public {
        bool authorized = _proofHash == keccak256(abi.encodePacked(publicKey, privateKey));
        require(authorized, "Invalid proof hash");
        enlisted[msg.sender] = true;
    }
}
```

The `Enlistment` contract is the actual challenge. Even for someone who is not familiar with Solidity, the logic should be pretty straightforward. The constructor is called once on contract initialization and takes a `bytes32` key and splits it into two `bytes16` variables: `publicKey` and `privateKey`. The `enlist()` function takes a `_proofHash` as input and checks if it is equal to the keccak256 hash (common hashing function for EVM contracts) of the public and private keys concatenated. If the hash is valid, the player gets enlisted.    
Some visibility modifiers are used in the contract. The `enlist` function is public, meaning it can be called by anyone. The `publicKey` variable is also public, meaning that it can be read by anyone and the Solidity compiler will automatically embed a getter function for it in the final deployed on-chain bytecode. This is also the function called by the setup contract indeed in the `isSolved()` function. The `privateKey` variable is private, meaning it can only be accessed from within the contract itself.  
Note that the `private` modifier doesn't mean the variable cannot be read by external accounts. Even though the naming could be a bit misleading, every smart contract developer should know that **everything in the blockchain is public**, which by the way it also one of main blockchain features.  

But, how to actually read it? This time, the compiler won't provide a getter function for it, meaning we need to find another way around to read it. Luckily, in JSON-RPC endpoints (the piece of software that allows a client/user to easily interact with the blockchain), a `eth_getStorageAt` method exists that allows us to read the raw storage of a contract. The storage is where all the global state of the contract is stored, and it is organized in "slots" as key-value pairs. Each slot is 32 bytes, and the contract starts storing its variables from slot 0.  
In that specific case, the `publicKey` and `privateKey` variables are both of type `bytes16`, meaning they can be packed into a single storage slot. This memory layout optimization is done by the Solidity compiler, again, at compile time. This behavior can also be verified using the `forge inspect Enlistment storage` command on the `Enlistment` contract, that will output the following:

```shell
➜ forge inspect Enlistment storage

╭------------+--------------------------+------+--------+-------+-------------------------------╮
| Name       | Type                     | Slot | Offset | Bytes | Contract                      |
+===============================================================================================+
| publicKey  | bytes16                  | 0    | 0      | 16    | src/Enlistment.sol:Enlistment |
|------------+--------------------------+------+--------+-------+-------------------------------|
| privateKey | bytes16                  | 0    | 16     | 16    | src/Enlistment.sol:Enlistment |
|------------+--------------------------+------+--------+-------+-------------------------------|
| enlisted   | mapping(address => bool) | 1    | 0      | 32    | src/Enlistment.sol:Enlistment |
╰------------+--------------------------+------+--------+-------+-------------------------------╯
```

In fact, both `publicKey` and `privateKey` are stored in the same storage slot (slot 0).   

At this point, once the player gets a grasp on that concepts, it should be straightforward to try to read the storage zero slot, get both `publicKey` and `privateKey` from it, compute the `keccak256` hash of it and pass it to the `enlist()` function.  
Actually, as the most attentive ones will notice, there is also another way to solve the challenge: since, once again, ***everything on the blockchain is public***, another way to get the needed `publicKey` and `privateKey` is to find the transaction initialized by `Setup.sol` that deployed `Enlistment.sol` where the arguments to the constructor are also passed, and so the `_key` parameter needed in order to solve the challenge.


# Exploitation
The final solve script can be assembled in many ways. As the embedded documentation in the challenge states, one can even just interact with the JSON-RPC endpoints via raw HTTP requests using for example `curl`. The standalone `cast` cli tool provided by the Foundry toolset is also just enough to solve this challenge, via the `cast storage` subcommand to read storage slots, `cast keccak` to compute the hash and `cast send` to send the function call to `enlist()`. 

However, a more convenient solution (especially for the following challenges) is to write a solve script that uses `web3.py` library (or any other library like the js respective `web3.js` library, `ethers.js`, etc), or by using Foundry cheatcodes. Any similar framework could also work.

The official solution for this challenge uses `web3.py` and can be fully read [here](./htb/solver.py). The focus point of the script are the following lines:

```python
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    [...]
    key = w3.eth.get_storage_at(target_addr, 0)
    private_key, public_key = (key[:16], key[16:32])
    [...]
    proof_hash = w3.keccak(public_key + private_key)
    [...]
    csend(target_addr, "enlist(bytes32)", proof_hash.hex())
```
