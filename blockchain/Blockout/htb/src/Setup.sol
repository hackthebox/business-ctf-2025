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
