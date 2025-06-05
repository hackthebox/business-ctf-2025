// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract VCNKv2CompatibleReceiver is Initializable, UUPSUpgradeable {
    bytes32 private constant _KERNEL_SLOT = // bytes32(uint256(keccak256("eip1967.proxy.kernel")) - 1);
        0xdfd6aae0422f0f1b088cd021e8b6cc6f05946fda71574e498556c210a58d3f01;

    uint256 public constant MAX_VAULT_CAPACITY = 100 ether;
    uint256 public energyVault;
    event EnergyDelivered(address indexed sender, uint256 amount);
    
    modifier onlyKernel() {
        require(msg.sender == _kernel(), "[VCNKv2CompatibleReceiver] Unauthorized: kernel only");
        _;
    }

    function initialize() external initializer onlyProxy {
        address kernel = msg.sender;
        assembly {
            sstore(_KERNEL_SLOT, kernel)
        }
    }

    function deliverEnergy(uint256 amount) external onlyProxy returns (bool) {
        require(
            energyVault + amount <= MAX_VAULT_CAPACITY,
            "[VCNKv2CompatibleReceiver] Power delivery exceeds maximum vault capacity"
        );
        energyVault += amount;
        emit EnergyDelivered(msg.sender, amount);
        return true;
    }

    function healthcheck() external view onlyProxy returns (bool) {
        return (
            _kernel() != address(0) &&
            energyVault <= MAX_VAULT_CAPACITY
        );
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyKernel onlyProxy {}
    
    function _kernel() internal view onlyProxy returns (address k) {
        assembly { k := sload(_KERNEL_SLOT) }
    }
}
