// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/*
  _   __     __                      _____         __           ___            __  _  __         __               __ __                 __
 | | / /__  / /__  ___ ___ _____ _  / ___/__ ___  / /________ _/ (_)__ ___ ___/ / / |/ /_ ______/ /__ ___ _____  / //_/__ _______  ___ / /
 | |/ / _ \/ / _ \/ _ `/ // / _ `/ / /__/ -_) _ \/ __/ __/ _ `/ / /_ // -_) _  / /    / // / __/ / -_) _ `/ __/ / ,< / -_) __/ _ \/ -_) / 
 |___/\___/_/_//_/\_,_/\_, /\_,_/  \___/\__/_//_/\__/_/  \_,_/_/_//__/\__/\_,_/ /_/|_/\_,_/\__/_/\__/\_,_/_/   /_/|_|\__/_/ /_//_/\__/_/  
                      /___/                                                                                                               
                                                      Volnaya Centralized Nuclear Kernel
*/

interface vcnkCompatibleReceiver {
  function deliverEnergy(uint256 amount) external returns (bool);
}

contract VCNK {
  ControlUnit public controlUnit;
  mapping(address => Gateway) public gateways;

  uint8 constant CU_STATUS_IDLE = 1;
  uint8 constant CU_STATUS_DELIVERING = 2;
  uint8 constant CU_STATUS_EMERGENCY = 3;
  uint8 constant GATEWAY_STATUS_UNKNOWN = 0;
  uint8 constant GATEWAY_STATUS_IDLE = 1;
  uint8 constant GATEWAY_STATUS_ACTIVE = 2;
  uint8 constant MAX_GATEWAYS = 5;
  uint256 constant MAX_CAPACITY = 100 ether;
  uint256 constant MAX_ALLOWANCE_PER_GATEWAY = 10 ether;
  uint256 constant GATEWAY_REGISTRATION_FEE = 20 ether;
  uint256 constant FAILSAFE_THRESHOLD = 10 ether;

  struct ControlUnit {
    uint8 status;
    uint256 registeredGateways;
    uint256 currentCapacity;
    uint256 allocatedAllowance;
  }
  
  struct Gateway {
    uint8 status;
    uint256 quota;
    uint256 totalUsage;
  }

  event GatewayRegistered(address indexed gateway);
  event GatewayQuotaIncrease(address indexed gateway, uint256 quotaAmount);
  event PowerDeliveryRequest(address indexed gateway, uint256 powerAmount);
  event PowerDeliverySuccess(address indexed gateway, uint256 powerAmount);
  event ControlUnitEmergencyModeActivated();

  modifier failSafeMonitor() {
    if (controlUnit.currentCapacity <= FAILSAFE_THRESHOLD) {
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

  constructor() {
    controlUnit.status = CU_STATUS_IDLE;
    controlUnit.currentCapacity = MAX_CAPACITY;
    controlUnit.allocatedAllowance = 0;
  }

  function registerGateway(address _gateway) external payable circuitBreaker failSafeMonitor {
    require(
      controlUnit.registeredGateways < MAX_GATEWAYS,
      "[VCNK] Maximum number of registered gateways reached. Infrastructure will be scaled up soon, sorry for the inconvenience."
    );
    require(msg.value == GATEWAY_REGISTRATION_FEE, "[VCNK] Registration fee must be 20 ether.");
    Gateway storage gateway = gateways[_gateway];
    require(gateway.status == GATEWAY_STATUS_UNKNOWN, "[VCNK] Gateway is already registered.");
    gateway.status = GATEWAY_STATUS_IDLE;
    gateway.quota = 0;
    gateway.totalUsage = 0;
    controlUnit.registeredGateways += 1;
    emit GatewayRegistered(_gateway);
  }

  function requestQuotaIncrease(address _gateway) external payable circuitBreaker failSafeMonitor {
    require(msg.value > 0, "[VCNK] Deposit must be greater than 0.");
    Gateway storage gateway = gateways[_gateway];
    require(gateway.status != GATEWAY_STATUS_UNKNOWN, "[VCNK] Gateway is not registered.");
    uint256 currentQuota = gateway.quota;
    require(currentQuota + msg.value <= MAX_ALLOWANCE_PER_GATEWAY, "[VCNK] Requested quota exceeds maximum allowance per gateway.");
    gateway.quota += msg.value;
    controlUnit.allocatedAllowance += msg.value;
    emit GatewayQuotaIncrease(_gateway, msg.value);
  }

  function requestPowerDelivery(uint256 _amount, address _receiver) external circuitBreaker failSafeMonitor {
    Gateway storage gateway = gateways[_receiver];
    require(gateway.status == GATEWAY_STATUS_IDLE, "[VCNK] Gateway is not in a valid state for power delivery.");
    require(_amount > 0, "[VCNK] Requested power must be greater than 0.");
    require(_amount <= gateway.quota, "[VCNK] Insufficient quota.");
    
    emit PowerDeliveryRequest(_receiver, _amount);
    controlUnit.status = CU_STATUS_DELIVERING;
    controlUnit.currentCapacity -= _amount;

    vcnkCompatibleReceiver(_receiver).deliverEnergy(_amount);
    gateway.totalUsage += _amount;

    controlUnit.currentCapacity = MAX_CAPACITY;
    emit PowerDeliverySuccess(_receiver, _amount);
  }
}
