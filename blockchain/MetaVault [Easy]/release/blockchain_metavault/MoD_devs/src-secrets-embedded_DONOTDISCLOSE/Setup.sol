pragma solidity 0.8.25;

import {MetaVault} from "./MetaVault.sol";

contract Setup {
    MetaVault public immutable TARGET;

    constructor() payable {
        TARGET = new MetaVault();
        TARGET.deposit{value: 100 ether}();
    }

    function isSolved() public view returns (bool) {
        return address(TARGET).balance == 0;
    }
}