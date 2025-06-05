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
