# Spectral

22<sup>nd</sup> May 2025  
Prepared By: perrythepwner  
Challenge Author(s): **perrythepwner**  
Difficulty: <font color=green>Easy</font>

---

# TLDR
The `VCNK.sol` contract acts as a power plant, delivering on-demand power to arbitrary contracts that implement the `vcnkCompatibleReceiver` interface. The `VCNK` contract is missing the Checks-Effects-Interactions (CEI) pattern in `requestPowerDelivery`, and its reentrancy guard (`require(msg.sender == tx.origin)`) is obsolete after the EVM Pectra upgrade (EIP-3074 / EIP-7702). An attacker can therefore bypass the guard via a delegated EOA, recursively call `requestPowerDelivery` in their `deliverEnergy` callback, drive the control unit's capacity below the fail-safe threshold, and trigger Emergency Mode.

# Description
> A new nuclear power plant called "VCNK" has been built in Volnaya, and the dominance of the energy lobby is now stronger than ever. You have been assigned to Operation "Blockout" and your mission is to find a way to disrupt the power plant to slow them down. See you in the dark!

# Skills Required
- Basic understanding of Solidity and smart contracts
- Interaction with smart contracts
- Basic understanding of reentrancy attacks

# Skills Learned
- Reentrancy attacks after Pectra upgrade and EIP-7702

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { VCNK } from "./VCNK.sol";

contract Setup {
    VCNK public TARGET;

    event DeployedTarget(address at);

    constructor() {
        TARGET = new VCNK();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        uint8 CU_STATUS_EMERGENCY = 3;
        (uint8 status, , , ) = TARGET.controlUnit();
        return status == CU_STATUS_EMERGENCY;
    }
}

```

The `Setup.sol` contract, as common for blockchain challenges, simply instantiates a fresh `VCNK` contract and implements the `isSolved` function used by the server to check if the challenge's solve criteria are met. The requirements are that the `ControlUnit` status of the `VCNK` contract is set to `CU_STATUS_EMERGENCY`.


## `VCNK.sol`

### Prague/Electra (Pectra) hardfork
First of all, an important detail is that in the `foundry.toml` file, the `VCNK` contract is set to be deployed with the "Prague" hardfork.

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
evm_version = "prague"
```

"Prague" and "Electra" were supposed to be two different upgrades for Ethereum, but they were merged into one upgrade called "Pectra". The [Pectra upgrade](https://ethereum.org/en/roadmap/pectra/) includes updates to both the execution layer and the consensus layer of the Ethereum network. One of the most relevant changes in this upgrade is the implementation of EIP-7702, which allows user accounts (EOA) to be extended with smart contract code, effectively allowing them to act as smart contracts and therefore make use of some the [Account Abstraction](https://ethereum.org/en/roadmap/account-abstraction/) concepts. For example:
- **Transaction Batching**: EOAs can now batch multiple operations into a single transaction, reducing gas fees and improving efficiency.
- **Gas sponsorship** (meta-txs): Third parties (dApps, relayers, or service providers) can pay gas on behalf of end users. Account X signs an authorization so that account Y's EOA can execute code and have its gas fees covered without Y holding ETH.
- **Programmable Wallets**: EOAs can now have programmable logic, allowing for more complex interactions, such as multi-signature wallets, time-locked accounts, and more.

> More details about the Pectra upgrade: https://ethereum.org/en/roadmap/pectra/

Allowing EOAs to execute smart contract code means that the `msg.sender` of a transaction can now be the EOA itself, which has never been possible before. Therefore, the Pectra upgrade broke some past assumptions used for example for security measures, such as reentrancy guards of the form `require(msg.sender == tx.origin)`. While that pattern was a valid (and cheap, because storing lock-like variables in global storage is expensive) reentrancy guard before the Pectra upgrade, it is now useless. This challenge focuses on this aspect of the Pectra upgrade, and how it can be concretely exploited.

### Core Logic

Regarding the `VCNK` contract, the code mainly revolves around a `ControlUnit` struct stored in contract state, along with a per-address `Gateway` struct mapping. The `ControlUnit` holds the kernel status and state:
- `ControlUnit.currentCapacity`: holds the current power capacity of the plant (how much power can be delivered). After each successful power delivery, this value is reset to `MAX_CAPACITY`. If that value drops below `FAILSAFE_THRESHOLD`, the `failSafeMonitor` modifier sets the ControlUnit status to **Emergency Mode**.
- `ControlUnit.status`: indicates the current status of the control unit (idle, delivering, emergency).
- `ControlUnit.allocatedAllowance`: the total amount of power that the overall gateways can request.

The contract logic requires users to register via the `registerGateway` and pay a 20 ETH fee, in order to register an arbitrary `Gateway` contract address into the `gateways` mapping. After that, they can top up their individual quotas (up to 10 ETH) via `requestQuotaIncrease`.

The heart of the protocol is `requestPowerDelivery`. This function first checks that the caller's gateway is in the idle state and that the requested amount does not exceed its current quota. It then emits a delivery request event, sets the control unit status to delivering, and subtracts the desired amount from `controlUnit.currentCapacity`. Only after these steps does it perform the external call to `vcnkCompatibleReceiver(_receiver).deliverEnergy(_amount)`. As already mentioned, the `vcnkCompatibleReceiver` contract can be arbitrary, meaning we have execution flow control. Only after the external `deliverEnergy` callback execution, the `gateway.totalUsage` is updated with the requested amount, and the `controlUnit.currentCapacity` is reset back to `MAX_CAPACITY`. This is a common **missing Checks-Effects-Interactions (CEI) pattern**, potentially leading to reentrancy vulnerabilities.

As already mentioned, the `circuitBreaker` modifier, supposed to break reentrancy attempts, is basically useless after the Pectra upgrade, and because the external interaction happens before the updates to the gateway's usage and before re-setting state, an attacker can reenter `requestPowerDelivery` during the `deliverEnergy` callback to repeatedly drain capacity and trigger Emergency Mode on the CU.

# Exploitation
While the main attack vector is a textbook reentrancy exploit, the EIP-7702 EOA->Contract delegation might not be so straightforward, especially in these early stages of the upgrade. Moreover, at the time of writing, the Foundry's [`signDelegation`](https://book.getfoundry.sh/cheatcodes/sign-delegation) cheatcode seems broken (I still provided the wannabe foundry exploit [here](./htb/foundry-solver/) because I lost time before realizing foundry was just broken :/).  
The [snakecharmers blog post](https://snakecharmers.ethereum.org/7702/) does a great job explaining EIP-7702 at both a high level and a low level, and also how to concretely implement it using `web3.py`, which is also used for the solve script [here](./htb/web3py-solver/solver.py).

The attack flow is as follows:
1. Deploy a malicious `Exploit.sol` that implements the `vcnkCompatibleReceiver` interface
2. In its `deliverEnergy(uint256 amount)` callback, check the plant's remaining capacity and recursively call `requestPowerDelivery(amount, attackerEOA)` again until the `ControlUnit` capacity is below the `FAILSAFE_THRESHOLD`  
3. Sign a delegation authorization (type 4 TX) against your EOA using `sign_authorization` web3.py method
4. Register the malicious contract as a gateway 
5. Call `requestQuotaIncrease` function to increase the quota of the malicious gateway to 10 ETH
6. Call `requestPowerDelivery` with the maximum amount (10 ETH) to trigger the reentrancy exploit

The full exploitation script is available [here](./htb/web3py-solver/solver.py).
