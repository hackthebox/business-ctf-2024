pragma solidity 0.8.25;

import {Recruitment} from "./Recruitment.sol";

contract Setup {
    Recruitment public immutable TARGET;

    constructor() payable {
        TARGET = new Recruitment{value: 1 wei}();
    }

    function isSolved() public view returns (bool) {
        return TARGET.isRecruited(msg.sender);
    }
}
