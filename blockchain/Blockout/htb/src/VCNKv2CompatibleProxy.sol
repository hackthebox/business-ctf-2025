// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

contract VCNKv2CompatibleProxy {
    bytes32 private constant _IMPLEMENTATION_SLOT = // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _impl, bytes memory _initData) {
        assembly {
            sstore(_IMPLEMENTATION_SLOT, _impl)
        }

        if (_initData.length > 0) {
            (bool ok, bytes memory err) = _impl.delegatecall(_initData);
            require(ok, string(err));
        }
    }

    fallback() external payable { _forward(); }
    receive() external payable { _forward(); }

    function _forward() private {
        assembly {
            let impl := sload(_IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            return(0, returndatasize())
        }
    }
}
