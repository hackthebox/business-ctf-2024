// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Brokenswap} from "./Brokenswap.sol";
import {FeesPool} from "./FeesPool.sol";
import {WETH9} from "./WETH9.sol";
import {HTBtoken} from "./HTBtoken.sol";

contract Setup {
    Brokenswap public immutable TARGET;
    FeesPool public immutable feesPool;
    WETH9 public immutable weth;
    HTBtoken public immutable htb;

    constructor(address _player) payable {
        require(msg.value == 510 ether, "Setup: wrong amount of ETH");

        // deploying both HTB and WETH token
        htb = new HTBtoken(500e18);
        weth = new WETH9();

        // deploying FeesPool with dual pair WETH/HTB
        feesPool = new FeesPool(address(weth), address(htb));

        // wrapping ETH to WETH
        weth.deposit{value: 500 ether}();

        // deploying Brokenswap with 0.5% swap fee 
        TARGET = new Brokenswap(address(weth), address(htb), 5, address(feesPool));

        // sending 1:1 tokens to pool reserves
        weth.transfer(address(TARGET), 500e18);
        htb.transfer(address(TARGET), 500e18);

        // player starts with 10 WETH
        weth.deposit{value: 10 ether}(); 
        weth.transfer(_player, 10e18);
    }

    function isSolved() public view returns (bool) {
        return (weth.balanceOf(msg.sender) >= 15e18);
    }
}
