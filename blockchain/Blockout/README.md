# Blockout

22<sup>nd</sup> May 2025 \
Prepared By: perrythepwner \
Challenge Author(s): **perrythepwner** \
Difficulty: <font color=orange>Medium</font>

---

# TLDR
The `VCNKv2` contract is a Contract Factory for "gateway" contracts, not trusting anymore arbitrary ones as the previous version. Each gateway contract follows the UUPS Proxy pattern, with a custom implementation of the `Proxy.sol` contract. The `Proxy.sol` contract has a missing check on the low-level `delegatecall` return value in the `_forward` function, allowing failing transactions in the implementation contract to be executed without reverting. Due to the nature of the UUPS pattern, the implementation contract holds the `initialize` initializer function, that is called by `VCNKv2` when deploying new gateway contracts. By registering new gateways within an artificially low gas transaction (“undergassing”), the `initialize()` call runs Out Of Gas and fails silently, leaving the proxy in a uninitialized state and with `_KERNEL_SLOT` empty. By taking over multiple gateway contracts in a 51% like attack, an attacker can trigger the kernel Emergency Mode via the `infrastructureSanityCheck()` function. 

# Description
> Amazing job, Agent P. Volnaya's "VNCK" power plant was shut down due to irreparable damage to their infrastructure, leaving a mark in the history books as the "GreatBl@ck0Ut attack". However, due to their wealth and the resilience of their APT group, they were able to go back online with a new, more powerful, and secure power grid called "VCNKv2". As the final act of Operation "Blockout" we need to take down the new kernel. I know you can do it.

# Skills Required
- Basic understanding of Solidity and smart contracts
- Interaction with smart contracts
- Familiarity with Proxy Contract patterns (UUPS, delegatecall)

# Skills Learned
- Auditing custom Proxy implementations  
- Crafting an “undergassing” attack on EVM.

# Challenge Scenario
Volnaya’s original `VNCKv1` was compromised in the *GreatBl@ck0Ut attack*. They rolled out `VCNKv2` as a hardened replacement, adding:
- A failsafe that only triggers emergency mode if >50% of gateways are deadlocked  
- A built-in factory (`VCNKv2`) that only deploys audited, UUPS-compatible gateways  
- A `ControlUnit` that tracks gateway health and enforces aggregated capacity

Your mission is to find a way to trick the kernel into `CU_STATUS_EMERGENCY` mode, despite these protections.

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { VCNKv2 } from "./VCNKv2.sol";

contract Setup {
    VCNKv2 public TARGET;

    event DeployedTarget(address at);

    constructor(uint8 _nGateways) {
        TARGET = new VCNKv2(_nGateways);
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        uint8 CU_STATUS_EMERGENCY = 3;
        (uint8 status, , , , ) = TARGET.controlUnit();
        return status == CU_STATUS_EMERGENCY;
    }
}
```

The target contract is deployed with `_nGateways` passed at deployment by deployer account, we can check the exact number by looking into the constructor args passed to the `Setup` contract deployed at the zero block (`cast block 0` to inspect).  
To solve the challenge, as the V1 challenge required, we need to trigger the `CU_STATUS_EMERGENCY` status.


## `VCNKv2.sol`, `VCNKv2CompatibleProxy.sol` and `VCNKv2CompatibleReceiver.sol`

The `VCNKv2` contract appears to be almost the same as the previous `VNCK` challenge contract, just with some more robustness and features. Again, the contract is deployed on the "prague" hardfork, and the reentrancy check modifier `circuitBreaker` remained the same. However, the previously vulnerable function, `requestPowerDelivery`, better follows the CEI pattern on critical storage variables.

```solidity
function requestPowerDelivery(uint256 _amount, uint8 _gatewayID) external circuitBreaker failSafeMonitor {
    Gateway storage gateway = controlUnit.registeredGateways[_gatewayID];
    require(controlUnit.status == CU_STATUS_IDLE, "[VCNK] Control unit is not in a valid state for power delivery.");
    require(gateway.status == GATEWAY_STATUS_IDLE, "[VCNK] Gateway is not in a valid state for power delivery.");
    require(_amount > 0, "[VCNK] Requested power must be greater than 0.");
    require(_amount <= gateway.availableQuota, "[VCNK] Insufficient quota.");
    
    emit PowerDeliveryRequest(_gatewayID, _amount);
    controlUnit.status = CU_STATUS_DELIVERING;
    controlUnit.currentCapacity -= _amount;
    gateway.status = GATEWAY_STATUS_ACTIVE;
    gateway.totalUsage += _amount;

    bool status = VCNKv2CompatibleReceiver(gateway.addr).deliverEnergy(_amount);
    require(status, "[VCNK] Power delivery failed.");

    controlUnit.currentCapacity = MAX_CAPACITY;
    gateway.status = GATEWAY_STATUS_IDLE;
    emit PowerDeliverySuccess(_gatewayID, _amount);
  }
```

It's still updating `controlUnit.currentCapacity` after the external interaction, but critically, now the gateway usage tracking is moved up before the external call, making the reentrancy useless. Also, 
a `require(controlUnit.status == CU_STATUS_IDLE)` check is added making reentrancy completely unexploitable.  
Moreover, reading the updated `registerGateway` function, now users cannot arbitrary register their own gateways contracts but instead the contract will deploy its own gateway contracts via the `_deployGateway` internal function. 

```solidity
function _deployGateway(uint8 id) internal {
    VCNKv2CompatibleReceiver impl = new VCNKv2CompatibleReceiver();
    VCNKv2CompatibleProxy proxy = new VCNKv2CompatibleProxy(
        address(impl),
        ""
    );
    controlUnit.registeredGateways[id] = Gateway(
      address(proxy),
      GATEWAY_STATUS_IDLE,
      0,
      0
    );
    controlUnit.latestRegisteredGatewayID++;
    VCNKv2CompatibleReceiver(address(proxy)).initialize();
  }
```

The new gateway contracts are upgradable contracts, meaning that the gateway actually becomes two contracts that follows the proxy-implementation pattern: one is the **proxy contract**, which its only job is to hold the "memory" of the "implementation contract". The other one is **implementation contract** is where the actual contract logic happen (so called "implementation"), and this is the actual "upgradable" contract. Since the proxy contract also stores the address of the implementation contract, an authorized user can just change this storage slot to point to a new implementation contract, effectively upgrading the contract logic that passes through the proxy.  
How is that actually done though? Low-level speaking, the proxy contract is basically a glorified `delegatecall`, and since this peculiar opcode allows to delegate the execution of a function to another contract while keeping the same storage context, the delegated contract will only change the storage of the proxy contract.  
A basic understanding of proxy patterns is required to solve this challenge, so if you are not familiar with it, better explanations can be found in the [RareSkills blog posts](https://www.rareskills.io/proxy-patterns) or in the [OpenZeppelin documentation](https://docs.openzeppelin.com/upgrades-plugins/proxies).  
Usually, such patterns, as delicate as they can be, they gets standardized and then OpenZeppelin libraries provide a robust implementation of them. In our scenario the `VCNKv2CompatibleReceiver` does in fact import OZ's `Initializable` and `UUPSUpgradeable` contracts, but the `VCNKv2CompatibleProxy` doesn't.  
Since the implementation contracts also holds both the initializing and the upgrade logic, it is said to be an [UUPS upgradeable contract](https://www.rareskills.io/post/uups-proxy). **Critically, in such patterns, as well for the UUPS ones, the initialization doesn't happen in the constructor, but rather in a separate initializer function**. While this can be a safe practice if done as intended, this 2-step pattern inevitably opens to more attack vectors, and points of failure. This challenges does in fact demonstrate an attack scenario when this can be exploited.  

Shifting the focus back to the custom proxy implementation, `VCNKv2CompatibleProxy`, and comparing to a [basic OpenZeppelin proxy contract implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/Proxy.sol), we won't see much of a difference at first glance. However, one critical check is missing: ***the return data of the delegatecall is not checked, meaning any failing proxied call won't revert the transaction, potentially leaving to inconsistent states.***  

Great! this sound exploitable, isn't it? **Let's imagine the `initialize()` function called by the `VCNKv2` factory fails when deploying a new Gateway contract... The transaction will not be reverted, leaving the deployed implementation contract `VCNKv2CompatibleReceiver` uninitialized!** Moreover, the `initialize()` doesn't have a whitelist for who can initialize the contract, but instead it assumes that the calles is the Factory contract itself and store its address in the `_KERNEL_SLOT` storage slot, which by the way has high privileges as it can authorize upgrades and therefore upgrade the implementation contract to an arbitrary one. For the sake of the challenge, it is enough to just leave the `_KERNEL_SLOT` empty, as the `healthcheck()` function will return false if the `_kernel()` is `address(0)`, marking the gateway be treates as in a `DEADLOCK` state. If at least 51% of the registered gateways are in a `DEADLOCK` state, the `infrastructureSanityCheck()` function will trigger the `CU_STATUS_EMERGENCY` status needed to solve the challenge.  

The goal now becomes clear: call `registerGateway` and make the **deployment** of the new gateway contract succeed, but make the **initialization** somehow fail. Doing this for enough gateways in a 51%-like attack and we win. 

# The "undergassing" attack
When I started writing the challenge, I wanted to have a "factory->proxy->uninitialized" type of attack scenario, but I still didn't have a clear idea of how possibly achieve such scenario without making also the contract deployment fail. Moreover, I wanted to be as much as realistic as possible, and therefore having a clean logic other than the missing return value check. I started questioning myself if this would be even possible, since the attacker wouldn't control none of the inputs, execution flow, or environment... but here is when I made the realization that an attacker triggering the contract deployment via the `registerGateway()` function actually has "input control" over a critical parameter that is then passed around during all the execution flow: ***the gas limit!***.  
I started looking in the wild for such attack scenario, but I didn't found many references and thought it would be a cool idea to implement for the challenge and potentially bring more awareness on this attack vector.

In the context of this challenge, given the previous analysis, **the idea is to pass a gas limit value such that the `VCNKv2CompatibleProxy` contract is deployed successfully, but the subsequent `initialize()` on `VCNKv2CompatibleReceiver` will internally run out of gas (OOG) and fail silently, leaving the proxy in an uninitialized state.**   

The attack steps are as follows:
1) The attacker calls `registerGateway()` function with purposefully accurate low gas limit.
2) The `VCNKv2` factory deploys a new `VCNKv2CompatibleProxy` contract, the transaction shouldn't go OOG here.
3) The factory then calls `VCNKv2CompatibleReceiver(address(proxy)).initialize()`, the proxy forwards the call to the `VCNKv2CompatibleReceiver` contract via `delegatecall` with the remaining gas limit while retaining a `1/64` portion of it because of the [63/64 gas rule](https://www.rareskills.io/post/eip-150-and-the-63-64-rule-for-gas) for external calls in EVM.
4) The `initialize()` function is called with so little gas that it runs out of gas while executing.
5) The `delegatecall` receives an OOG exception in the `r` return value, but it's not checked. The proxy contract does not revert and returns normally because of the small portion of gas left saved before the call.
6) The factory has registered the new gateway address but left it uninitialized.
7) Repeat from step 1) for enough gateways to reach the 51% threshold of deadlocked gateways.


# Exploitation

Well... this is funny. On paper, the attack shouldn't be too much of a trouble to implement, just a few tries with binary search on different gas limits until we find the sweet spot. The fact is that Foundry for example does two-step simulations in scripts before broadcasting the transaction, and if it fails it won't be broadcasted at all. The funny part starts here: since the simulations will never be 100% accurate, and given that our attack can be sensitive to even the smallest amount unit of gas, it may happen that the simulation will succeed/fail on some calls but that won't actually happen on the broadcasted transaction.  
In fact, my exploit never fails on any call on the simulation...

![🎣](./assets/foundry_simulation.png)

but once it gets broadcasted it will actually fail on `initialize()` and make us win.  

![win](./assets/win_tx.png)


The exploit is essentially just the following:

```solidity
for (uint8 i = 0; i < 5; i++) {
    target.registerGateway{ value: 20 ether, gas: 1_150_500 }();
    console2.log("registered gateway", i);
}
target.infrastructureSanityCheck();
target.infrastructureSanityCheck();
( uint8 status, , , , ) = target.controlUnit();
console2.log("Control Unit status:", status);
```

And upon reading `target.controlUnit()` we will see the status field equal to 3 (Emergency Mode), satisfying the challenge solve requirements.  

See the full exploitation script [here](./htb/script/Exploit.s.sol).
