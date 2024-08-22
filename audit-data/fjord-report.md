---
title: Protocol Audit Report
author: RaazyMuhd11
date: May 26, 2024
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
        \includegraphics[width=0.5\textwidth]{logo.pdf} 
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries Puppy Raffle Audit Report\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape Cyfrin.io\par}
    \vfill
    {\large \today\par}
\end{titlepage}

\maketitle

<!-- Your report starts here! -->

Prepared by: [RaazyMuhd11](https://github.com/raazymuhd11)
Lead Auditors: 
- RaazyMuhd11

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Total Issues found](#total-issues-found)
- [Findings](#findings)
  - [\[L-1\]: Centralization Risk for trusted owners](#l-1-centralization-risk-for-trusted-owners)
  - [\[L-2\]: `PuppyRaffle:getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly they have not entered the raffle.](#l-2-puppyrafflegetactiveplayerindex-returns-0-for-non-existent-players-and-for-players-at-index-0-causing-a-player-at-index-0-to-incorrectly-they-have-not-entered-the-raffle)
  - [\[L-3\]: Define and use `constant` variables instead of using literals](#l-3-define-and-use-constant-variables-instead-of-using-literals)
  - [\[4\]: Event is missing `indexed` fields](#4-event-is-missing-indexed-fields)
  - [\[L-5\]: PUSH0 is not supported by all chains](#l-5-push0-is-not-supported-by-all-chains)
  - [Gas \& Informational Issues](#gas--informational-issues)
  - [\[I-1\]: Solidity pragma should be specific, not wide](#i-1-solidity-pragma-should-be-specific-not-wide)
  - [\[I-2\]: Missing checks for `address(0)` when assigning values to address state variables](#i-2-missing-checks-for-address0-when-assigning-values-to-address-state-variables)
  - [\[I-3\]: `PuppyRaffle::selectWinner` does not follow CEI, which is not a best practice.](#i-3-puppyraffleselectwinner-does-not-follow-cei-which-is-not-a-best-practice)
  - [\[I-4\]: Use of "magic" numbers is discouraged](#i-4-use-of-magic-numbers-is-discouraged)
  - [\[I-5\] State changes are missing events](#i-5-state-changes-are-missing-events)
  - [\[I-6\] `PuppyRaffle::_isActivePlayer` is never used and should be removed.](#i-6-puppyraffle_isactiveplayer-is-never-used-and-should-be-removed)
  - [\[G-1\] Unchanged state variables should be declared as constant or immutable](#g-1-unchanged-state-variables-should-be-declared-as-constant-or-immutable)
  - [\[G-2\] Storage variables in a loop should be cached](#g-2-storage-variables-in-a-loop-should-be-cached)

# Protocol Summary

 write about the protocol summary here

# Disclaimer

 I'm making all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 
    - Commit Hash: `e30d199697bbc822b646d76533b66b7d529b8ef5`

## Scope 
  ```
    ./src/
    └── PuppyRaffle.sol
  ```

## Roles
  Owner - Deployer of the protocol, has the power to change the wallet address to which fees are sent through the changeFeeAddress function. Player - Participant of the raffle, has the power to enter the raffle with the enterRaffle function and refund value through refund function.

# Executive Summary
    I loved auditing this codebase. Raazy is such a wizard at writing intentionally bad code.

## Total Issues found

| Severity | Number of issues found |
| --------- | ---------------------- |
| High      | 4                      |
| Medium    | 2                      |
| Low       | 2                      |
| Info      | 9                      |
| Total     | 17                     |


# Findings


## [L-1]: Centralization Risk for trusted owners

Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

- Found in src/PuppyRaffle.sol [Line: 18](src\PuppyRaffle.sol#L18)

	```solidity
	contract PuppyRaffle is ERC721, Ownable {
	```

- Found in src/PuppyRaffle.sol [Line: 182](src\PuppyRaffle.sol#L182)

	```solidity
	    function changeFeeAddress(address newFeeAddress) external onlyOwner {
	```

## [L-2]: `PuppyRaffle:getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly they have not entered the raffle.	

**Description**  If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```solidity
  function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```



## [L-3]: Define and use `constant` variables instead of using literals

If the same constant literal value is used multiple times, create a constant state variable and reference it throughout the contract.

- Found in src/PuppyRaffle.sol [Line: 140](src\PuppyRaffle.sol#L140)

	```solidity
	        uint256 prizePool = (totalAmountCollected * 80) / 100;
	```

- Found in src/PuppyRaffle.sol [Line: 141](src\PuppyRaffle.sol#L141)

	```solidity
	        uint256 fee = (totalAmountCollected * 20) / 100;
	```

- Found in src/PuppyRaffle.sol [Line: 150](src\PuppyRaffle.sol#L150)

	```solidity
	        uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
	```



## [4]: Event is missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

- Found in src/PuppyRaffle.sol [Line: 53](src\PuppyRaffle.sol#L53)

	```solidity
	    event RaffleEnter(address[] newPlayers);
	```

- Found in src/PuppyRaffle.sol [Line: 54](src\PuppyRaffle.sol#L54)

	```solidity
	    event RaffleRefunded(address player);
	```

- Found in src/PuppyRaffle.sol [Line: 55](src\PuppyRaffle.sol#L55)

	```solidity
	    event FeeAddressChanged(address newFeeAddress);
	```



## [L-5]: PUSH0 is not supported by all chains

Solc compiler version 0.8.20 switches the default target EVM version to Shanghai, which means that the generated bytecode will include PUSH0 opcodes. Be sure to select the appropriate EVM version in case you intend to deploy on a chain other than mainnet like L2 chains that may not support PUSH0, otherwise deployment of your contracts will fail.

- Found in src/Reentrancy.sol [Line: 2](src\Reentrancy.sol#L2)

	```solidity
	pragma solidity ^0.8.13;
	```


**Impact** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting alot of gas.

**Proof Of Concept**
 1. User enter the raffle, they are the first entrant.
 2. `PuppyRaffle::getActivePlayerIndex` returns 0.
 3. Use thinks they not entered correctly due to the function documentation.


**Recommended Mitigation** The easiest recomendation would be to revert if the player is not in the array instead of returning 0.

you could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active.

 
## Gas & Informational Issues

## [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in script/DeployPuppyRaffle.sol [Line: 2](script\DeployPuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

- Found in src/PuppyRaffle.sol [Line: 2](src\PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

- Found in src/Reentrancy.sol [Line: 2](src\Reentrancy.sol#L2)

	```solidity
	pragma solidity ^0.8.13;
	```

## [I-2]: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

- Found in src/PuppyRaffle.sol [Line: 62](src\PuppyRaffle.sol#L62)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 183](src\PuppyRaffle.sol#L183)

	```solidity
	        feeAddress = newFeeAddress;
	```

## [I-3]: `PuppyRaffle::selectWinner` does not follow CEI, which is not a best practice.

 It's best to keep code clean and follow CEI (Checks, Effects, Interactions)

```diff
-    	(bool success,) = winner.call{value: prizePool}("");
-        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+    	(bool success,) = winner.call{value: prizePool}("");
+        require(success, "PuppyRaffle: Failed to send prize pool to winner");
```


## [I-4]: Use of "magic" numbers is discouraged

It can be confusing to see number literal in a codebase, and its much more readable if the numbers are given a name.

Examples: 
```solidity
	 uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;
```

Instead, use could use:
```solidity
	uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
	uint256 public constant FEE_PERCENTAGE = 20;
	uint256 public constant POOL_PRECISION = 100;
```

## [I-5] State changes are missing events


## [I-6] `PuppyRaffle::_isActivePlayer` is never used and should be removed.



## [G-1] Unchanged state variables should be declared as constant or immutable

 reading from storage is much more expensive than reading from a constant or immutable variable
 
 Instances:
   - `PuppyRaffle::RaffleDuration` should be `immutable`
   - `PuppyRaffle::commonImageUri` should be `contant`
   - `PuppyRaffle::rareImageUri` should be `contant`
   - `PuppyRaffle::legendaryImageUri` should be `contant`

## [G-2] Storage variables in a loop should be cached

  Everytime you call `players.length` you are reading from storage, as opposed to memory which is more gas efficient

  ```diff
+	 uint256 playersLength = players.length;

	  // @audit check for duplicates
-        for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playersLength - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
  ```