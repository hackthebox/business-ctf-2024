<h1 style="text-align: center; font-size: 300%;">Brokenswap Docs</h1>
<i style="display: block; text-align: center; font-size: 100%;">"people said i was broke so i funded Brokenswap"</i>

# Overview

Brokenswap is a Decentralized Exchange (DEX) for exchanging cryptocurrencies (ERC-20 Tokens) on the Ethereum blockchain. Brokenswap is designed as an Automated Market Maker (AMM) based on the Costant Product Market Maker (CPMM) model. The entire model is ruled by the `x*y = k` function to provide always infinity liquidity to users.

# Table of Contents

1. **Introduction**
   - Smart Contracts
   - What is a Decentralized Exchange (DEX)?
   - What is an ERC-20 Token?
   - Liquidity Pools
   - Trading Pairs
   - The Constant Product Formula: `x*y = k`

2. **Developers Documentation**
   - Direct interaction with the Smart Contracts
   - API Spefication
   - Direct interaction with the blockchain
   - Short Foundry Tutorial
      - Calling a view function
      - Calling a normal function
      - Initializing a forge project
      - Deploying a Contract
   - Contract Sources
      - Setup.sol
      - Other source files

# 1. Introduction

## Smart Contracts

A "Smart Contract" is simply a program that runs on the Ethereum blockchain. It's a collection of code (its functions) and data (its state) that resides at a specific address on the Ethereum blockchain.  
Smart contracts are programmed with a high-level language called [Solidity](https://docs.soliditylang.org/en/v0.8.21/). To create a DApp (Decentralized Application) and publish the code to the blockchain, the Solidity code is transformed into operational codes ([OP_CODES](https://www.evm.codes/)) and then into a bytecode. This bytecode is finally deployed and executed by the EVM ([Ethereum Virtual Machine](https://ethereum.org/en/developers/docs/evm/)) to perform the specified operations. All this means that the EVM can function like a real computer, performing from the simplest to the most complex operations.

Smart contracts are a type of [Ethereum account](https://ethereum.org/en/developers/docs/accounts/). This means they have a balance and can be the target of transactions. However they're not controlled by a user, instead they are deployed to the network and run as programmed. User accounts can then interact with a smart contract by submitting transactions that execute a function defined on the smart contract. As everything in the blockchain, they are immutable and transparent.

## What is a Decentralized Exchange (DEX)?

A Decentralized Exchange (DEX) is a type of cryptocurrency exchange that operates on a blockchain and allows users to trade cryptocurrencies directly with one another without the need for an intermediary or central authority. Due to its decentralized nature, there's no registration or account required of its users.  
DEXs utilize smart contracts to facilitate and automate the trading process.  
For example, When a user in Brokenswap wants to trade one cryptocurrency for another, they send their assets to our smart contract, which will consequently send the counterpart token based on the exchange rate given by the Liquidity Pools.

## What is an ERC-20 Token?

ERC-20 tokens are a common standard for fungible tokens on the Ethereum blockchain. They adhere to a set of rules and specifications that enable interoperability between various decentralized applications (DApps) and exchanges.  
These tokens are used for a wide range of purposes: reputation points in an online platform, skills of a character in a game, lottery tickets, financial assets like a share in a company, a fiat currency like USD, an ounce of gold, etc...  
The ERC-20 (Ethereum Request for Comments, number 20), proposed by Fabian Vogelsteller in November 2015, is a Token Standard that implements an API for tokens within Smart Contracts. From [EIP-20](https://eips.ethereum.org/EIPS/eip-20):  

Methods
```solidity
function name() public view returns (string)
function symbol() public view returns (string)
function decimals() public view returns (uint8)
function totalSupply() public view returns (uint256)
function balanceOf(address _owner) public view returns (uint256 balance)
function transfer(address _to, uint256 _value) public returns (bool success)
function transferFrom(address _from, address _to, uint256 _value) public returns (bool success)
function approve(address _spender, uint256 _value) public returns (bool success)
function allowance(address _owner, address _spender) public view returns (uint256 remaining)
```

- `name` (optional): Token full name, e.g "Wrapped Ethereum".  
- `symbol` (optional): An acronym of few letters to recognize the token, e.g "WETH".  
- `decimal` (optional): The number of decimal places that the token can be divided into (e.g, a token with 18 decimal places can be divided into 10^18 units).  
- `totalSupply`: The total supply of tokens that have been created . 
- `balanceOf`: The balance of tokens held by a particular address.  
- `transfer`: This function allows an address to send tokens to another address.  
- `transferFrom`: This function allows an address to transfer tokens from another address that has approved them to do so.  
- `approve`: This function allows an address to approve another address to spend tokens on their behalf.  
- `allowance`: The amount of tokens that an approved address can spend on behalf of another address.  

Events
```solidity
event Transfer(address indexed _from, address indexed _to, uint256 _value)
event Approval(address indexed _owner, address indexed _spender, uint256 _value)
```
- `Transfer`: An event triggered when a transfer is successful.  
- `Approval`: A log of an approved event (an event).  

In other words, ERC-20 tokens are nothing else than a smart contract that implements with their logics the interface standardized by ERC20 to create interoperability and compatibility in the ecosystem.  
The implementation used in Brokenswap for the HTB token is the [OpenZeppelin implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol).

## Liquidity Pools

Liquidity pools are a fundamental component of Decentralized Exchanges. These pools play a crucial role in ensuring that users can easily and efficiently trade various ERC-20 tokens on the Ethereum blockchain without the need for traditional order books or centralized intermediaries.

In a traditional exchange, liquidity is typically provided by market makers who create buy and sell orders to facilitate trading. However, in a decentralized exchange like Brokenswap, liquidity is sourced from Liquidity Pools. Whose provides liquidity to Liquidity Pools is often referred to as liquidity providers, incentivized by earning a commission for each transaction.  
_Currently, in Brokenswap, the only liquidity provider is the contract itself with it's reserves, which retains a 0.5% fee for each swap._

<div style="display: flex; align-items: center; flex-direction: column; text-align: center;">
   <img src="images/uniswap-dual-pool-example.png" alt="Uniswap Liquidity Pools example" style="width: 65%; height: 65%; margin-bottom: 10px;">
   <p style="width: 60%; margin: 0;">Image from <a href="https://uniswapv3book.com/docs/introduction/introduction-to-markets/" title="Uniswap V3 Docs">Uniswap V3 Docs</a></p>
</div>

## Trading Pairs

Trading pairs represent the two cryptocurrencies being traded. For example, in the Ethereum/Bitcoin trading pair, users can exchange Ethereum for Bitcoin and vice versa.  
_Currently, the only supported trading pairs in Brokenswap are WETH/HTB and HTB/WETH._

<div style="display: flex; align-items: center; flex-direction: column; text-align: center;">
   <img src="images/uniswap-liquidity-pools.png" alt="Uniswap Liquidity Pools example" style="width: 65%; height: 65%; margin-bottom: 10px;">
   <p style="width: 60%; margin: 0;">Image from <a href="https://docs.uniswap.org/contracts/v2/concepts/core-concepts/pools" title="Uniswap V2 Docs">Uniswap V2 Docs</a></p>
</div>

## The Constant Product Formula: `x*y = k`

The "constant product” formula `x*y = k` is a key concept in automated market makers (AMMs) like Brokenswap.  
This formula states that trades must not change the product (k) of a pair’s reserve balances (x and y). Because k remains unchanged from the reference frame of a trade, it is often referred to as the **Invariant**.  
In the `x*y = k` formula:
- `x` represents the amount of TokenA in the Liquidity Pool.
- `y` represents the amount of TokenB in the Liquidity Pool.
- `k` is the constant value determined when liquidity is initially added.

During a swap from TokenA to TokenB, user deposit `x` amount of TokenA in the Liquidity Pool, meaning that the amount of TokenA in the pool will increase. However, the product of `x` and `y` must remain constant (or invariant), so the amount of TokenB in the pool must decrease.  
To calculate the new TokenB balance (y) is simple as that:

```
y = k/x
```

<div style="display: flex; align-items: center; flex-direction: column;">
   <img src="images/constant-product-formula.webp" alt="Constant Product Formula" style="width: 90%; height: 90%; margin-bottom: 10px;">
   <span> Constant Product Formula </span>
</div>

### Example:
1) Vitalik wants to swap 10 WETH for HTB in Brokenswap. The initial balances in the pool are 50 WETH and 50 HTB. Then the invariant (k) is `50*50 = 2500`.
2) Vitalik calls the `swap()` function, depositing 10 WETH. Now there are 60 WETH in the pool.  
3) Brokenswap calculates the balance (y) of HTB token needed to mantain the invariant:  
`y = k/x`  
`y = 2500/60 = 41.66666...` HTB tokens
4) The HTB token that Vitalik will receive is:  
`y - y' = 50 - 41.66666 = 8.33333...` HTB tokens

As you may have noticed, even if initially the ratio between WETH and HTB in the pool was 1:1, Vitalik didn't experienced a 1:1 swap. That's makes sense because of the law of supply and demand, that says: "if the supply goes up, the price must fall", i.e high demand increases the price. The 10 WETH Vitalik had, did in fact lost value after he managed to increase WETH balance in the pool.  
*_Looking at the graph, you'll note also that the pool never runs out of liquidity, instead the more scarce TokenA becomes, the more its value compared to a TokenB will grow exponentially, and vice versa._*  

Still not clear? Take a look <a href="https://uniswapv3book.com/docs/introduction/constant-function-market-maker/">here</a>

<div style="display: flex; align-items: center; flex-direction: column; text-align: center;">
   <img src="images/swap-workflow.jpg" alt="Swap workflow" style="width: 90%; height: 90%; margin-bottom: 10px;">
   <p style="width: 60%; margin: 0;">Swap workflow, Image from <a href="https://docs.uniswap.org/contracts/v2/concepts/core-concepts/pools" title="Uniswap V2 Docs">Uniswap V2 Docs</a></p>
</div>


As previously said, the Brokenswap protocol takes 0.5% fees on each swap since it's the only liquidity provider. This won't alter the mechanism since fees are deducted from the input amount that's initializing the swap.  
_Fees are then collected in a separeted pool, called "FeesPool", where only the Brokenswap owner can withdraw._

### Example with fees:
1) Vitalik wants to swap 10 WETH for HTB in Brokenswap. The initial balances in the pool are 50 WETH and 50 HTB. Then the invariant (k) is `50*50 = 2500`.
2) Vitalik calls the `swap()` function, depositing 10 WETH. Now there are 60 WETH in the pool. 
3) Before making any transaction or calculation, the protocol deduct fees on the input amount:
   - `10 WETH * 5/1000 = 0.05 WETH`  
   --> 0.05 WETH are sent to the FeesPool address.
   From now all the steps are identical to before, but as if Vitalik had deposited 9.95 WETH instead of 10.
4) Brokenswap calculates the balance (y) of HTB token needed to mantain the invariant:  
`y = k/x`  
`y = 2500/59.95 = 41.70141784820684` HTB tokens
5) The HTB token that Vitalik will receive is:  
`y - y' = 50 - 41.70141784820684 = 8.298582151793163` HTB tokens
6) Invariant `k = x*y = 59.95*41.70141784820684 = 2500`

You can see how the invariant is unchanged, since the calculation of the fees takes place on the surplus that the user deposits and does not alter the starting balance of the pool in any way. Compared to before, the user will simply receive fewer HTB tokens in exchange.

This is even more evident if HTB tokens are exchanged for WETH again:
1) Vitalik deposit back `8.298582151793163` HTB tokens, the protocol move out 0.05% to feesPool.  
   Now HTB balance is: `41.70141784820684 + (8.298582151793163 - (8.298582151793163 * 5/1000)) = 49.95850708924104`
2) `x = k/y`  
   `x = 2500/49.95850708924104 = 50.04152737259026`
3) The WETH token that Vitalik will receive is:  
   `x - x' = 59.95 - 50.04152737259026 = 9.908472627409743`

As you can see, Vitalik got back his WETH tokens, but lost roughly ~`0.05*2` WETH tokens in fees.  
Meanwhile, in the Liquidity Pool:  
- Invariant remained invariant: `x*y = 49.9585*50.0415 = 2500`
- Sum of HTB + WETH tokens it's back to how it was originally: `49.9585+50.0415 = 100`  

In the FeesPool:
- Roughly 0.05 WETH and 0.05 HTB tokens are collected.

# 2. Developers Documentation

## API Spefication

This section provides a brief description of the web app's endpoints.
- `/swap`: The endpoint to swap tokens with a user friendly interface.
- `/docs`: The endpoint to access this documentation.
- `/restart`: Restarts the local chain without restarting the entire container.
- `/rpc`: The RPC endpoint used for interacting with the network.
- `/connection`: This endpoint provides the necessary information for interacting with the challenge, including:
  - User's private key.
  - User's wallet address.
  - Setup contract's address.
  - Challenge contracts addresses.

## Direct interaction with the blockchain

To interact with the smart contracts on the private chain, you will need:

- A private key with some Ether, which is provided via the `/connection` endpoint.
- The address of the target contract. You can find both the Setup's and the Target's addresses in the `/connection` or retrieve the target's address using the `TARGET()` function within the `Setup` contract.
- The RPC URL, which is the `/rpc` endpoint.

Once you have collected all the connection information, you can use tools like `web3py` or `web3js` to make function calls in the smart contracts or perform other necessary actions. You can find useful tutorials for both options with a quick online search.
Alternatively, you can utilize tools such as `foundry-rs` or `hardhat` as convenient command-line interfaces (CLI) to interact with the blockchain. Please note that there may be fewer online examples available for these tools compared to the other alternatives. Since we prefer using foundry, we will provide a brief tutorial.

## Short Foundry Tutorial

The foundry docs can be found [here](https://book.getfoundry.sh/). The purpose of this guide is to get you up to speed a little quicker and get you to familiarize yourselves with foundry and not actually teach you all of its capabilities.

### Calling a view function

In Solidity, `view` functions are used to read data without making any changes to the blockchain state. You can identify these functions by the `view` modifier in their declaration, such as `function isSolve() public view;`. To call these functions, you don't need to sign a transaction; you can simply query for data using the `cast` tool with the following command:

`cast call $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL`

If the function requires arguments, you need to specify the argument types within braces and provide their values outside the string, like this:

`cast call $ADDRESS_TARGET "functionWithArgs(uint, bool)" 5 true --rpc-url $RPC_URL`

### Calling a normal function

To call a function that modifies data, you need to sign the transaction. These functions are any non-view and non-pure functions in Solidity. You can use the `cast` tool again with the following command:

`cast send $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY`

If the function has arguments, you follow the same pattern as before:

`cast send $ADDRESS_TARGET "functionWithArgs(uint)" 100 --rpc-url $RPC_URL --private-key $PRIVATE_KEY`

Additionally, some functions may be marked as `payable`, which means they can accept Ether along with the call. You can specify the value using the `--value` flag:

`cast send $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY --value 100`

### Initializing a forge project

To create and deploy smart contracts, we will use another tool called `forge` from the `foundry-rs` suite. You can initialize an empty forge project using the command:

`forge init .`

You can optionally use flags like `--no-git` to skip initializing a Git repository and other useful options. The project will contain the following directories and files:

- `src/`: This is where you write your smart contracts. It initially contains an example contract called `Counter.sol`.
- `test/`: This is where you write tests. There is an example test file called `Counter.t.sol`. You can run these tests using the `forge test` command. Feel free to explore this feature on your own as it is highly useful but beyond the scope of our discussion.
- `script/`: This folder is used for scripts, which are batch Solidity commands that run on-chain. An example script could be a deployment script. The folder contains an example script called `Counter.s.sol`. You can execute these scripts using `forge script script/Counter.s.sol` along with additional flags based on your requirements. Feel free to experiment with this feature as it is extremely useful.
- `lib/`: This is where you place any libraries. By default, there is only one library called `forge-std`, which includes useful functions for debugging and testing. You can download additional libraries using the `forge install` command. For example, you can install the commonly used `openzeppelin-contracts` library from the OpenZeppelin repository with `forge install openzeppelin/openzeppelin-contracts`.
- `foundry.toml`: This is the configuration file for forge. You usually don't need to deal with it during exploitation, but it is helpful for development purposes.

### Deploying a Contract

The final step is to deploy a smart contract after completing the coding. This can be done using the `forge` tool. The command is as follows:

`forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY`

After executing this command, the deployer's address (which is essentially our address), the transaction hash, and the deployed contract's address will be printed on the screen. The deployed contract's address is the one we need to use for interacting with it.

If our contract has a payable `constructor`, we can use the `--value` flag in the same way as in the `cast send` command:

`forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY --value 10000`

Additionally, if the constructor has arguments, we can specify them using the `--constructor-args` flag and provide the arguments in the same order they appear in the constructor. For example, if the constructor is defined as `constructor(uint256, bytes32, bool)`, we would use the following command:

`forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args 14241 0x123456 false`

You can combine multiple flags and there are more flags available that we haven't mentioned here. However, these are the most common ones. It is highly recommended to explore the tools while solving the challenges, as they greatly simplify the process. Other options to consider are `hardhat` (JavaScript) or `brownie` (Python), which use different programming languages instead of Solidity.

## Contract Sources

In these challenges, you will encounter two types of smart contract source files: `Setup.sol` and the challenge files.

### Setup.sol

The `Setup.sol` file contains a single contract called `Setup`. This contract handles all the initialization actions. It typically includes three functions:  

- `constructor()`: Automatically called once during contract deployment and cannot be called again. It performs initialization actions such as deploying the challenge contracts.
- `TARGET()`: Returns the address of the challenge contract.
- `isSolved()`: Defines the final objective of the challenge. It returns `true` if the challenge is solved, and `false` otherwise.

### Other source files

The remaining files consist of the challenge contracts. You need to interact with these contracts to solve the challenge. Carefully analyze their source code to understand how to exploit vulnerabilities, based on the objective specified in the `isSolved()` function of the `Setup` contract.
Here's a quick glance on the functionalities of the challenge contracts:

#### Brokenswap.sol

`_moveAmountToFeesPool(address token, uint256 amount)`  
**Description**: Internal function to move a specified amount of token to the fees pool.

`balanceOfToken(address token)`  
**Description**: Get the balance of a supported token held by the contract.

`calcOutputAmount(address inputToken, address outputToken)`  
**Description**: Calculate the output amount for a given input and output token pair.

`constructor()`  
**Description**: Constructor to initialize the Brokenswap contract.

`swap(address inputToken, address outputToken, uint256 amount)`  
**Description**: Swaps one supported token for another.



<!--- STYLING -->
<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@500&family=Orbitron:wght@700&display=swap');

code {
   font-family: 'Fira Code', monospace;
   color: crimson;
   background-color: #212429;
   padding: 2px;
   font-size: 105%;
}

em {
   font-style: italic;
   color: #333;
   background-color: #f7f7f7;
   border-radius: 4px;
   box-shadow: 2px 2px 3px rgba(0, 0, 0, 0.1);
}

strong, b {
   font-weight: bold; 
   text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.4);
}

a {
   text-decoration: none;
   color: #FD0079;
   transition: color 0.3s;
}

a:hover {
  color: #e570ff;
  text-decoration: underline;
}

</style>
<!--- STYLING -->
