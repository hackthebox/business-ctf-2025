// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/*
  _   __     __                      _____         __           ___            __  _  __         __               __ __                 __  _   _____ 
 | | / /__  / /__  ___ ___ _____ _  / ___/__ ___  / /________ _/ (_)__ ___ ___/ / / |/ /_ ______/ /__ ___ _____  / //_/__ _______  ___ / / | | / /_  |
 | |/ / _ \/ / _ \/ _ `/ // / _ `/ / /__/ -_) _ \/ __/ __/ _ `/ / /_ // -_) _  / /    / // / __/ / -_) _ `/ __/ / ,< / -_) __/ _ \/ -_) /  | |/ / __/ 
 |___/\___/_/_//_/\_,_/\_, /\_,_/  \___/\__/_//_/\__/_/  \_,_/_/_//__/\__/\_,_/ /_/|_/\_,_/\__/_/\__/\_,_/_/   /_/|_|\__/_/ /_//_/\__/_/   |___/____/ 
                      /___/                                                                                                                           
                                                      Volnaya Centralized Nuclear Kernel V2

                              ╔═════════════ VCNK v2.0 Release Notes + GreatBl@ck0Ut attack PostMortem ══════════════╗
                              ║ The GreatBl@ck0Ut attack that recently occurred on our infrastructure corrupted logs ║
                              ║ and state on all of our nodes permanently. In accordance with validators, we had to  ║
                              ║ roll back to a stable state, losing most of the VCNK v1.0 data and transactions.     ║
                              ║ We therefore decided to re-deploy the VCNK with improved security measures.          ║
                              ║                                                                                      ║
                              ║ Changelog:                                                                           ║
                              ║ ~ More tolerant failsafe mechanism: a single gateway will no longer be able to       ║
                              ║   trigger emergency mode again. Kernel will enter emergency mode only if >50% of     ║
                              ║   gateways are unavailable.                                                          ║
                              ║ ~ Gateways are now tamper-proof: VCNKv2 becomes also a factory for predefined,       ║
                              ║   audited, and upgradable gateway contracts.                                         ║
                              ║ ~ ControlUnit now tracks registered gateways by unique IDs.                          ║
                              ╚══════════════════════════════════════════════════════════════════════════════════════╝
*/

import { VCNKv2CompatibleReceiver } from "./VCNKv2CompatibleReceiver.sol";
import { VCNKv2CompatibleProxy } from "./VCNKv2CompatibleProxy.sol";

contract VCNKv2 {
  ControlUnit public controlUnit;
  
  uint8 constant CU_STATUS_IDLE = 1;
  uint8 constant CU_STATUS_DELIVERING = 2;
  uint8 constant CU_STATUS_EMERGENCY = 3;
  uint8 constant GATEWAY_STATUS_UNKNOWN = 0;
  uint8 constant GATEWAY_STATUS_IDLE = 1;
  uint8 constant GATEWAY_STATUS_ACTIVE = 2;
  uint8 constant GATEWAY_STATUS_DEADLOCK = 3;
  uint8 constant MAX_GATEWAYS = 20;
  uint256 constant MAX_CAPACITY = 100 ether;
  uint256 constant MAX_ALLOWANCE_PER_GATEWAY = 4 ether;
  uint256 constant GATEWAY_REGISTRATION_FEE = 20 ether;
  uint256 constant FAILSAFE_THRESHOLD = 10 ether;

  struct ControlUnit {
    uint8 status;
    uint8 healthyGatewaysPercentage;
    uint8 latestRegisteredGatewayID;
    mapping(uint8 => Gateway) registeredGateways;
    uint256 currentCapacity;
    uint256 allocatedAllowance;
  }
  
  struct Gateway {
    address addr;
    uint8 status;
    uint256 availableQuota;
    uint256 totalUsage;
  }

  event GatewayDeployed(uint8 id, address indexed user);
  event GatewayQuotaIncrease(uint8 indexed gatewayID, uint256 quotaAmount);
  event GatewayNeedsMantenance(uint8 indexed gatewayID);
  event PowerDeliveryRequest(uint8 indexed gatewayID, uint256 powerAmount);
  event PowerDeliverySuccess(uint8 indexed gatewayID, uint256 powerAmount);
  event ControlUnitEmergencyModeActivated();

  modifier failSafeMonitor() {
    if (controlUnit.currentCapacity <= FAILSAFE_THRESHOLD) {
      controlUnit.status = CU_STATUS_EMERGENCY;
      emit ControlUnitEmergencyModeActivated();
    }
    else if (controlUnit.healthyGatewaysPercentage < 50) {
      controlUnit.status = CU_STATUS_EMERGENCY;
      emit ControlUnitEmergencyModeActivated();
    }
    else {
      _;
    }
  }

  modifier circuitBreaker() {
    require(msg.sender == tx.origin, "[VCNK] Illegal reentrant power delivery request detected.");
    _;
  }

  constructor(uint8 _nGateways) {
    controlUnit.status = CU_STATUS_IDLE;
    controlUnit.healthyGatewaysPercentage = 100;
    controlUnit.latestRegisteredGatewayID = 0;
    controlUnit.currentCapacity = MAX_CAPACITY;
    controlUnit.allocatedAllowance = 0;

    for (uint8 id; id < _nGateways; id++) {
      _deployGateway(id);
    }
  }

  function registerGateway() external payable circuitBreaker failSafeMonitor {
    uint8 id = controlUnit.latestRegisteredGatewayID;
    require(
      id < MAX_GATEWAYS,
      "[VCNK] Maximum number of registered gateways reached. Infrastructure will be scaled up soon, sorry for the inconvenience."
    );
    require(msg.value == GATEWAY_REGISTRATION_FEE, "[VCNK] Registration fee must be 20 ether.");
    emit GatewayDeployed(controlUnit.latestRegisteredGatewayID, msg.sender);
    _deployGateway(id);
  }

  function infrastructureSanityCheck() external circuitBreaker failSafeMonitor {
    uint8 healthyGateways = 0;
    for (uint8 id = 0; id < controlUnit.latestRegisteredGatewayID; id++) {
      Gateway storage gateway = controlUnit.registeredGateways[id];
      bool isGatewayHealthy = VCNKv2CompatibleReceiver(gateway.addr).healthcheck();
      if (isGatewayHealthy) { healthyGateways++; }
      else {
        gateway.status = GATEWAY_STATUS_DEADLOCK;
        controlUnit.allocatedAllowance -= gateway.availableQuota;
        gateway.availableQuota = 0;
        emit GatewayNeedsMantenance(id);
      }
    }
    uint8 result = uint8((uint256(healthyGateways) * 100) / controlUnit.latestRegisteredGatewayID);
    controlUnit.healthyGatewaysPercentage = result;
  }

  function requestQuotaIncrease(uint8 _gatewayID) external payable circuitBreaker failSafeMonitor {
    Gateway storage gateway = controlUnit.registeredGateways[_gatewayID];
    require(msg.value > 0, "[VCNK] Deposit must be greater than 0.");
    require(gateway.status != GATEWAY_STATUS_UNKNOWN, "[VCNK] Gateway is not registered.");
    require(gateway.availableQuota + msg.value <= MAX_ALLOWANCE_PER_GATEWAY, "[VCNK] Requested quota exceeds maximum allowance per gateway.");
    gateway.availableQuota += msg.value;
    controlUnit.allocatedAllowance += msg.value;
    emit GatewayQuotaIncrease(_gatewayID, msg.value);
  }

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
}
