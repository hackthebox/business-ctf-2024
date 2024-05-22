// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title Brokenswap, "people said i was broke so i funded Brokenswap".
/// @notice AMM decentralized exchange (DEX) for swapping supported tokens with a fee mechanism.
contract Brokenswap {
    using SafeERC20 for IERC20;

    uint256 public INVARIANT; // The product (k) of the two token balances (x and y), given by: x*y=k.
    uint256 public immutable FEERATE; // The fee rate, expressed as a percentage (e.g., 5 for 0.5%).
    address public immutable feesPool; // The address where fees are collected.
    mapping(address => bool) public supportedTokens; // Mapping of supported tokens.
    
    event Swap(
        uint256 indexed inputAmount,
        uint256 indexed outputAmount,
        uint256 indexed fees
    );

    /// @notice Constructor to initialize the Brokenswap contract.
    /// @param tokenA The address of the first supported token.
    /// @param tokenB The address of the second supported token.
    /// @param feeRate The fee rate, expressed as a percentage (e.g., 5 for 0.5%).
    /// @param feesPoolAddress The address where fees are collected.
    constructor (address tokenA, address tokenB, uint256 feeRate, address feesPoolAddress) payable {
        FEERATE = (feeRate > 5) ? feeRate : 5; // Ensure the fee rate is at least 0.5%.
        feesPool = feesPoolAddress;
        supportedTokens[tokenA] = true;
        supportedTokens[tokenB] = true;
    }

    /// @notice Swaps one supported token for another.
    /// @param inputToken The address of the token we're swapping from.
    /// @param outputToken The address of the output token we're swapping to.
    /// @param inputAmount The amount of input token to swap, in 18 decimals. e.g inputAmount=1e18 to swap 1 token.
    /// @return A boolean indicating the success of the swap.
    function swap(address inputToken, address outputToken, uint256 inputAmount) public returns (bool) {
        // Check if the tokens are supported.
        require(supportedTokens[inputToken] == true && supportedTokens[outputToken] == true, "Token not supported");
        IERC20 inToken = IERC20(inputToken);
        IERC20 outToken = IERC20(outputToken);
        
        // Calculate the invariant before any transaction.
        INVARIANT = inToken.balanceOf(address(this)) * outToken.balanceOf(address(this));
        
        // Check if the user has allowed the contract to transfer the input amount.
        require(inToken.allowance(msg.sender, address(this)) >= inputAmount, "You must approve transfer first");
        
        // Depositing the input token amount from user into the contract.
        inToken.safeTransferFrom(msg.sender, address(this), inputAmount);
        
        // Deduct fees on the input token.
        uint256 fees = (inputAmount * FEERATE) / 1000;
        
        // Move swap fee to the fees pool.
        _moveAmountToFeesPool(address(inToken), fees); 
        
        // Calculate the output token amount to send to the user.
        uint256 _outputAmount = calcOutputAmount(address(inToken), address(outToken));
        
        // Transfer the output amount from contract to the user.
        outToken.safeTransfer(msg.sender, _outputAmount);
        
        // Emit the Swap event to log the transaction.
        emit Swap(inputAmount, _outputAmount, fees);
        
        return true;
    }

    /// @notice Internal function to move a specified amount of token to the fees pool.
    /// @param payingToken The address of the token used to pay fees.
    /// @param amount The amount to move to the fees pool.
    /// @return A boolean indicating the success of the transfer.
    function _moveAmountToFeesPool(address payingToken, uint256 amount) public returns (bool) {
        require(supportedTokens[payingToken] == true, "Token not supported");
        IERC20(payingToken).safeTransfer(feesPool, amount);
        return true;
    }

    /// @notice Calculate the output amount for a given input and output token pair.
    /// @param inputToken The address of the input token.
    /// @param outputToken The address of the output token.
    /// @return The calculated output amount.
    function calcOutputAmount(address inputToken, address outputToken) public view returns (uint256) {
        require(supportedTokens[inputToken] == true && supportedTokens[outputToken] == true, "Token not supported");
        uint256 balanceInToken = IERC20(inputToken).balanceOf(address(this));
        uint256 balanceOutToken = IERC20(outputToken).balanceOf(address(this));
        
        // Calculate the new output amount based on the invariant.
        uint256 newBalanceOutToken = INVARIANT / balanceInToken;
        return (balanceOutToken - newBalanceOutToken);
    }

    /// @notice Get the balance of a supported token held by the contract.
    /// @param token The address of the supported token.
    /// @return The balance of the token held by the contract.
    function balanceOfToken(address token) public view returns (uint256) {
        require(supportedTokens[token] == true, "Token not supported");
        return IERC20(token).balanceOf(address(this));
    }
}
