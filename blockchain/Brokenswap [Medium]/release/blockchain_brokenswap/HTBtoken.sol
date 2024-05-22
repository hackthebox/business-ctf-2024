// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title HTBtoken - Hazardous Trade Bunker token
/// @notice This contract implements the HTBtoken, an ERC-20 token, allowing transfers and management of token balances.
contract HTBtoken is ERC20 {
    /// @notice Constructor to initialize the HTBtoken contract.
    /// @param initialSupply The initial supply of HTB tokens to be minted and assigned to the contract creator.
    constructor(uint256 initialSupply) ERC20("Hazardous Trade Bunker token", "HTB") {
        _mint(msg.sender, initialSupply);
    }
}
