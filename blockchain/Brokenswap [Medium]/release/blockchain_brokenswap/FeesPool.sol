// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title FeesPool, collect and withdraw fees of swaps.
/// @notice This contract allows the owner to manage and withdraw fees collected in supported tokens.
contract FeesPool is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable tokenA; // The first supported token.
    IERC20 public immutable tokenB; // The second supported token.

    event FeesCollected(IERC20 token, uint256 amount, address indexed collector);
    event FeesWithdrawn(IERC20 token, uint256 amount, address indexed recipient);

    /// @notice Constructor to initialize the FeesPool contract.
    /// @param _tokenA The address of the first supported token.
    /// @param _tokenB The address of the second supported token.
    constructor(address _tokenA, address _tokenB) Ownable(msg.sender) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /// @notice Withdraw collected fees in tokenA.
    /// @param amount The amount of tokenA to withdraw.
    function withdrawFeesTokenA(uint256 amount) public onlyOwner {
        require(amount > 0, "Invalid withdrawal amount");
        tokenA.safeTransfer(msg.sender, amount);
        emit FeesWithdrawn(tokenA, amount, msg.sender);
    }

    /// @notice Withdraw collected fees in tokenB.
    /// @param amount The amount of tokenB to withdraw.
    function withdrawFeesTokenB(uint256 amount) public onlyOwner {
        require(amount > 0, "Invalid withdrawal amount");
        tokenB.safeTransfer(msg.sender, amount);
        emit FeesWithdrawn(tokenB, amount, msg.sender);
    }

    /// @notice Get the balance of tokenA held by the contract.
    /// @return The balance of tokenA held by the contract.
    function balanceTokenA() public view returns (uint256) {
        return tokenA.balanceOf(address(this));
    }

    /// @notice Get the balance of tokenB held by the contract.
    /// @return The balance of tokenB held by the contract.
    function balanceTokenB() public view returns (uint256) {
        return tokenB.balanceOf(address(this));
    }
}
