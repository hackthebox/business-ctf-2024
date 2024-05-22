pragma solidity 0.8.25;

import {NotADemocraticElection} from "./NotADemocraticElection.sol";

contract Setup {
    NotADemocraticElection public immutable TARGET;

    constructor() payable {
        TARGET = new NotADemocraticElection(
            bytes3("ALF"), "Automata Liberation Front",
            bytes3("CIM"), "Cyborgs Indipendence Movement"
        );
        TARGET.depositVoteCollateral{value: 100 ether}("Satoshi", "Nakamoto");
    }

    function isSolved() public view returns (bool) {
        return TARGET.winner() == bytes3("CIM");
    }
}
