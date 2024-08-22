## LightChaser-V3

### Generated for: Codehawks : Fjord

### Generated on: 2024-08-20

## Total findings: 99

### Total Medium findings: 2

### Total Low findings: 21

### Total Gas findings: 44

### Total NonCritical findings: 32

# Summary for Medium findings

| Number | Details | Instances |
|----------|----------|----------|
| [Medium-1] | Privileged functions can create points of failure | 9 |
| [Medium-2] | deposit/redeem functions found which implement accounting arithmetic vulnerable to the donation attack | 3 |
# Summary for Low findings

| Number | Details | Instances |
|----------|----------|----------|
| [Low-1] | Potential division by zero should have zero checks in place  | 1 |
| [Low-2] | Factory lacks existence checks  | 1 |
| [Low-3] | Contracts with multiple onlyXYZ modifiers where XYZ is a role can introduce complexities when managing privileges  | 2 |
| [Low-4] | Use of transferFrom()/transfer() rather than safeTransferFrom()/safeTransfer() for NFTs in will lead to the loss of NFTs  | 2 |
| [Low-5] | Arbitrary staking/deposit on a arbitrary token with an arbitrary amount has no checks to ensure token amount isn't type(uint256).max thus allowing wrong stake amount for certain tokens with custom logic such as cUSDCv3 | 3 |
| [Low-6] | Token supply should not be centralised at deployment | 1 |
| [Low-7] | Loss of precision | 2 |
| [Low-8] | Staking address can be changed | 1 |
| [Low-9] | Constant decimal values | 1 |
| [Low-10] | Events may be emitted out of order due to code not follow the best practice of check-effects-interaction | 1 |
| [Low-11] | Critical functions should have a timelock | 5 |
| [Low-12] | Consider implementing two-step procedure for updating protocol addresses | 4 |
| [Low-13] | SafeTransferLib does not ensure that the token contract exists | 1 |
| [Low-14] | transfer will always revert as the IERC20 interface mismatch | 1 |
| [Low-15] | Constructors missing validation | 1 |
| [Low-16] | Return values not checked for OZ EnumerableSet add/remove functions | 1 |
| [Low-17] | Functions calling contracts/addresses with transfer hooks are missing reentrancy guards | 14 |
| [Low-18] | Missing events in functions that are either setters, privileged or voting related | 7 |
| [Low-19] | Unsafe use of transfer()/transferFrom() with IERC20 | 6 |
| [Low-20] | Common tokens such as `WETH9` work differently on chains such a `Blast` which isn't taken into account during transfer calls. | 1 |
| [Low-21] | SafeTransferLib does not ensure that the token contract exists | 7 |
# Summary for NonCritical findings

| Number | Details | Instances |
|----------|----------|----------|
| [NonCritical-1] | Consider using time variables when defining time related variables  | 1 |
| [NonCritical-2] | Events regarding state variable changes should emit the previous state variable value | 1 |
| [NonCritical-3] | In functions which accept an address as a parameter, there should be a zero address check to prevent bugs | 10 |
| [NonCritical-4] | Default int values are manually set | 1 |
| [NonCritical-5] | Revert statements within external and public functions can be used to perform DOS attacks | 19 |
| [NonCritical-6] | Functions which are either private or internal should have a preceding _ in their name | 1 |
| [NonCritical-7] | Contract lines should not be longer than 120 characters for readability | 1 |
| [NonCritical-8] | Specific imports should be used where possible so only used code is imported | 2 |
| [NonCritical-9] | Not all event definitions are utilizing indexed variables. | 20 |
| [NonCritical-10] | Contracts should have all public/external functions exposed by interfaces | 28 |
| [NonCritical-11] | Functions within contracts are not ordered according to the solidity style guide | 2 |
| [NonCritical-12] | Emits without msg.sender parameter | 2 |
| [NonCritical-13] | A function which defines named returns in it's declaration doesn't need to use return | 1 |
| [NonCritical-14] | Constants should be on the left side of the comparison | 12 |
| [NonCritical-15] | Both immutable and constant state variables should be CONSTANT_CASE | 5 |
| [NonCritical-16] | Use of non-named numeric constants | 4 |
| [NonCritical-17] | Unused errors present | 2 |
| [NonCritical-18] | Empty bytes check is missing | 1 |
| [NonCritical-19] | Cyclomatic complexity in functions | 4 |
| [NonCritical-20] | Unused events present | 2 |
| [NonCritical-21] | Missing events in sensitive functions | 5 |
| [NonCritical-22] | A event should be emitted if a non immutable state variable is set in a constructor | 4 |
| [NonCritical-23] | Non constant/immutable state variables are missing a setter post deployment | 1 |
| [NonCritical-24] | Empty revert statement | 1 |
| [NonCritical-25] | Inconsistent checks of address params against address(0) | 1 |
| [NonCritical-26] | Simplify complex revert statements | 1 |
| [NonCritical-27] | Constructors should emit an event | 5 |
| [NonCritical-28] | Function call in event emit | 1 |
| [NonCritical-29] | Errors should have parameters | 62 |
| [NonCritical-30] | Constant state variables defined more than once | 1 |
| [NonCritical-31] | ERC777 tokens can introduce reentrancy risks | 4 |
| [NonCritical-32] | Custom implementation of a `roundUp` operation, consider using `mulDivUp` instead | 1 |
# Summary for Gas findings

| Number | Details | Instances | Gas |
|----------|----------|----------|----------|
| [Gas-1] | The usage of SafeMath is useless in solidity versions 0.8.0 and above hence wasting gas  | 2 | 0.0 |
| [Gas-2] | State variables used within a function more than once should be cached to save gas  | 1 | 300 |
| [Gas-3] | x + y is more efficient than using += for state variables (likewise for -=) | 9 | 405 |
| [Gas-4] | Public functions not used internally can be marked as external to save gas | 2 | 0.0 |
| [Gas-5] | Usage of smaller uint/int types causes overhead | 34 | 63580 |
| [Gas-6] | Use != 0 instead of > 0 | 4 | 48 |
| [Gas-7] | Default bool values are manually reset | 1 | 0.0 |
| [Gas-8] | Default int values are manually reset | 7 | 0.0 |
| [Gas-9] | For loops in public or external functions should be avoided due to high gas costs and possible DOS | 1 | 0.0 |
| [Gas-10] | Mappings used within a function more than once should be cached to save gas | 1 | 200 |
| [Gas-11] | Use assembly to check for the zero address | 5 | 0.0 |
| [Gas-12] | Divisions which do not divide by -X cannot overflow or underflow so such operations can be unchecked to save gas | 1 | 0.0 |
| [Gas-13] | State variables which are not modified within functions should be set as constants or immutable for values set at deployment | 1 | 0.0 |
| [Gas-14] | Divisions of powers of 2 can be replaced by a right shift operation to save gas | 1 | 0.0 |
| [Gas-15] | Structs can be packed into fewer storage slots | 3 | 22500 |
| [Gas-16] | Consider using OZ EnumerateSet in place of nested mappings | 2 | 4000 |
| [Gas-17] | Use assembly to emit events | 20 | 15200 |
| [Gas-18] | Use solady library where possible to save gas | 2 | 4000 |
| [Gas-19] | Using private rather than public for constants and immutables, saves gas | 5 | 0.0 |
| [Gas-20] | Mark Functions That Revert For Normal Users As payable | 9 | 2025 |
| [Gas-21] | Lack of unchecked in loops | 4 | 1200 |
| [Gas-22] | Where a value is casted more than once, consider caching the result to save gas | 2 | 0.0 |
| [Gas-23] | Use assembly to validate msg.sender | 3 | 0.0 |
| [Gas-24] | Simple checks for zero uint can be done using assembly to save gas | 4 | 96 |
| [Gas-25] | Using nested if to save gas | 6 | 216 |
| [Gas-26] | Optimize Storage with Byte Truncation for Time Related State Variables | 4 | 32000 |
| [Gas-27] | Using delete instead of setting mapping to 0 saves gas | 3 | 45 |
| [Gas-28] | Stack variable cost less than state variables while used in emiting event | 5 | 225 |
| [Gas-29] | Stack variable cost less than mappings while used in emiting event | 1 | 9 |
| [Gas-30] | Inline modifiers used only once | 1 | 0.0 |
| [Gas-31] | Use s.x = s.x + y instead of s.x += y for memory structs (same for -= etc) | 1 | 200 |
| [Gas-32] | Calling .length in a for loop wastes gas | 2 | 388 |
| [Gas-33] | Constructors can be marked as payable to save deployment gas | 5 | 0.0 |
| [Gas-34] | Assigning to structs can be more efficient | 2 | 520 |
| [Gas-35] | Use OZ Array.unsafeAccess() to avoid repeated array length checks | 4 | 33600 |
| [Gas-36] | State variable read in a loop | 2 | 57940 |
| [Gas-37] | Use uint256(1)/uint256(2) instead of true/false to save gas for changes | 4 | 272000 |
| [Gas-38] | Avoid emitting events in loops | 4 | 9000 |
| [Gas-39] | Write direct outcome, instead of performing mathematical operations for constant state variables | 1 | 0.0 |
| [Gas-40] | Consider pre-calculating the address of address(this) to save gas | 6 | 0.0 |
| [Gas-41] | Use 'storage' instead of 'memory' for struct/array state variables | 5 | 52500 |
| [Gas-42] | Public functions not called internally | 2 | 0.0 |
| [Gas-43] | Empty blocks should be removed or emit something | 2 | 0.0 |
| [Gas-44] | Using named returns for pure and view functions is cheaper than using regular returns | 4 | 416 |
## [Medium-1] Privileged functions can create points of failure

### Resolution 
Ensure such accounts are protected and consider implementing multi sig to prevent a single point of failure

Num of instances: 9

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner  // <= FOUND
```
['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L57)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner  // <= FOUND
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner  // <= FOUND
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution  // <= FOUND
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner  // <= FOUND
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner  // <= FOUND
```
['[357](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L357-L357)']
```solidity
357:     function addAuthorizedSablierSender(address _address) external onlyOwner  // <= FOUND
```
['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L361)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner  // <= FOUND
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L755)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin  // <= FOUND
```


</details>

## [Medium-2] deposit/redeem functions found which implement accounting arithmetic vulnerable to the donation attack

### Resolution 
Calculations using non-internal accounting, such as balanceOf or totalSupply, can introduce potential donation attack vectors. For instance, consider a scenario where a reward calculation uses totalSupply during a deposit. An attacker could exploit this by donating a large amount of tokens to the vault before the user tries to redeem their withdrawal. This manipulation causes the totalSupply to change significantly, altering the reward calculations and potentially leading to unexpected or unfair outcomes for users.

Let's say a smart contract calculates user rewards based on their share of the total token supply:

```solidity
uint256 reward = (userDeposit * totalRewards) / totalSupply;
```

If an attacker donates a large number of tokens to the vault before users withdraw, totalSupply increases, thereby diluting each user's share of the rewards. This discrepancy between expected and actual rewards can undermine user trust and contract integrity.

The risks associated with this attack include reward manipulation, where attackers can alter totalSupply to reduce the share of honest users, and economic attacks, where significant token donations destabilize the contract's economic assumptions, leading to unfair advantages or financial losses. Additionally, users may find their rewards significantly lower than expected, causing confusion and dissatisfaction.

To prevent such vulnerabilities, it's essential to use internal variables to track deposits, withdrawals, and rewards instead of relying on balanceOf or totalSupply. This approach isolates contract logic from external token movements. Implementing a snapshot mechanism to capture totalSupply at specific points in time ensures consistent reward calculations. Introducing limits on the number of tokens that can be deposited or donated in a single transaction can also prevent significant manipulation. 

Num of instances: 3

### Findings 


<details><summary>Click to show findings</summary>

['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L181)']
```solidity
181:     function auctionEnd() external { // <= FOUND
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded();
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled();
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) {
193:             auctionToken.transfer(owner, totalTokens);
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[691](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L691-L691)']
```solidity
691:     function _checkEpochRollover() internal { // <= FOUND
692:         uint16 latestEpoch = getEpoch(block.timestamp);
693: 
694:         if (latestEpoch > currentEpoch) {
695:             
696:             currentEpoch = latestEpoch;
697: 
698:             if (totalStaked > 0) {
699:                 uint256 currentBalance = fjordToken.balanceOf(address(this));
700: 
701:                 
702:                 uint256 pendingRewards = (currentBalance + totalVestedStaked + newVestedStaked)
703:                     - totalStaked - newStaked - totalRewards;
704:                 uint256 pendingRewardsPerToken = (pendingRewards * PRECISION_18) / totalStaked;
705:                 totalRewards += pendingRewards;
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
709:                 }
710:             } else {
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
714:                 }
715:             }
716: 
717:             totalStaked += newStaked;
718:             totalVestedStaked += newVestedStaked;
719:             newStaked = 0;
720:             newVestedStaked = 0;
721: 
722:             lastEpochRewarded = currentEpoch - 1;
723:         }
724:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L765)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin {
756:         
757:         if (_amount == 0) revert InvalidAmount();
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
764: 
765:         _checkEpochRollover(); // <= FOUND
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```


</details>

## [Low-1] Potential division by zero should have zero checks in place 

### Resolution 
Implement a zero address check for found instances

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[330](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L330-L332)']
```solidity
330:     function getEpoch(uint256 _timestamp) public view returns (uint16) { // <= FOUND
331:         if (_timestamp < startTime) return 0;
332:         return uint16((_timestamp - startTime) / epochDuration) + 1; // <= FOUND
333:     }
```


</details>

## [Low-2] Factory lacks existence checks 

### Resolution 
When utilizing a factory pattern to deploy contracts based on user input, it's crucial to ensure that the contract isn't being deployed at an address already in use. Deploying to an existing address can lead to unintentional overwrites or unexpected behavior. To prevent this, the factory contract should maintain a mapping or a list of deployed contract addresses. Before creating a new contract, the factory should check if the intended address is already in the list. If it is, the creation should be halted or rerouted. Implementing such checks minimizes risks, ensuring that contracts are only deployed to fresh, uncontaminated addresses, preserving the integrity of the protocol.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L58)']
```solidity
52:     function createAuction(
53:         address auctionToken, // <= FOUND
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address( // <= FOUND
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens);
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```


</details>

## [Low-3] Contracts with multiple onlyXYZ modifiers where XYZ is a role can introduce complexities when managing privileges 

### Resolution 
In smart contracts, using multiple `onlyXYZ` modifiers for different roles can complicate privilege management. OpenZeppelin's AccessControl offers a streamlined solution, enabling easier and more flexible role-based permission handling. It simplifies the assignment and revocation of roles compared to multiple individual modifiers, reducing potential errors and improving contract maintainability. This modular approach to access management makes it more straightforward to define, manage, and audit roles and permissions within a contract.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[14](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L14-L135)']
```solidity
14: contract FjordPoints is ERC20, ERC20Burnable, IFjordPoints {
15:     using SafeMath for uint256;
16: 
127:     modifier onlyOwner() { // <= FOUND
128:         if (msg.sender != owner) revert CallerDisallowed();
129:         _;
130:     }
131: 


135:     modifier onlyStaking() { // <= FOUND
136:         if (msg.sender != staking) {
137:             revert NotAuthorized();
138:         }
139:         _;


```
['[35](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L35-L325)']
```solidity
35: contract FjordStaking is ISablierV2LockupRecipient {
36:     
40:     using EnumerableSet for EnumerableSet.UintSet;
305:     modifier onlyOwner() { // <= FOUND
306:         if (msg.sender != owner) revert CallerDisallowed();
307:         _;
308:     }
309: 


310:     modifier onlyRewardAdmin() { // <= FOUND
311:         if (msg.sender != rewardAdmin) revert CallerDisallowed();
312:         _;
313:     }
314: 


325:     modifier onlySablier() { // <= FOUND
326:         if (msg.sender != address(sablier)) revert CallerDisallowed();
327:         _;
328:     }
329: 


```


</details>

## [Low-4] Use of transferFrom()/transfer() rather than safeTransferFrom()/safeTransfer() for NFTs in will lead to the loss of NFTs 

### Resolution 
When transferring ownership of NFTs, it's highly recommended to use the `safeTransferFrom()`/`safeTransfer()` function instead of `transferFrom()`/`transfer()`. `safeTransferFrom()`/`safeTransfer()` automatically checks if the recipient is a contract and if so, it must implement the `onERC721Received` function, complying with EIP-721 standard, to confirm the successful receipt of the NFT. This provides an additional safety measure to prevent tokens from being permanently lost when sent to contracts not designed to handle them. To add an extra layer of safety, consider implementing a function to allow the contract owner to return any NFTs sent to the contract by mistake. Regular audits and thorough testing of your contracts will help further ensure their security and reliability.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[397](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L397-L435)']
```solidity
397:     function stakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards { // <= FOUND
398:         
399:         if (!sablier.isStream(_streamID)) revert NotAStream();
400:         if (sablier.isCold(_streamID)) revert NotAWarmStream();
401: 
402:         
403:         if (!authorizedSablierSenders[sablier.getSender(_streamID)]) {
404:             revert StreamNotSupported();
405:         }
406:         if (address(sablier.getAsset(_streamID)) != address(fjordToken)) revert InvalidAsset();
407: 
408:         uint128 depositedAmount = sablier.getDepositedAmount(_streamID);
409:         uint128 withdrawnAmount = sablier.getWithdrawnAmount(_streamID);
410:         uint128 refundedAmount = sablier.getRefundedAmount(_streamID);
411: 
412:         if (depositedAmount - (withdrawnAmount + refundedAmount) <= 0) revert InvalidAmount();
413: 
414:         uint256 _amount = depositedAmount - (withdrawnAmount + refundedAmount);
415: 
416:         
417:         userData[msg.sender].unredeemedEpoch = currentEpoch;
418: 
419:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
420:         if (dr.epoch == 0) {
421:             dr.vestedStaked = _amount;
422:             dr.epoch = currentEpoch;
423: 
424:             _activeDeposits[msg.sender].add(currentEpoch);
425:         } else {
426:             dr.vestedStaked += _amount;
427:         }
428: 
429:         _streamIDs[msg.sender][_streamID] = NFTData({ epoch: currentEpoch, amount: _amount });
430:         _streamIDOwners[_streamID] = msg.sender;
431:         newStaked += _amount;
432:         newVestedStaked += _amount;
433: 
434:         
435:         sablier.transferFrom({ from: msg.sender, to: address(this), tokenId: _streamID }); // <= FOUND
436:         points.onStaked(msg.sender, _amount);
437: 
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount);
439:     }
```
['[521](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L521-L558)']
```solidity
521:     function _unstakeVested(address streamOwner, uint256 _streamID, uint256 amount) internal { // <= FOUND
522:         NFTData storage data = _streamIDs[streamOwner][_streamID];
523:         DepositReceipt storage dr = deposits[streamOwner][data.epoch];
524:         if (amount > data.amount) revert InvalidAmount();
525: 
526:         bool isFullUnstaked = data.amount == amount;
527:         uint16 epoch = data.epoch;
528: 
529:         dr.vestedStaked -= amount;
530:         if (currentEpoch != data.epoch) {
531:             totalStaked -= amount;
532:             totalVestedStaked -= amount;
533:             userData[streamOwner].totalStaked -= amount;
534:         } else {
535:             
536:             newStaked -= amount;
537:             newVestedStaked -= amount;
538:         }
539: 
540:         if (dr.vestedStaked == 0 && dr.staked == 0) {
541:             
542:             if (userData[streamOwner].unredeemedEpoch == currentEpoch) {
543:                 userData[streamOwner].unredeemedEpoch = 0;
544:             }
545:             delete deposits[streamOwner][data.epoch];
546:             _activeDeposits[streamOwner].remove(data.epoch);
547:         }
548:         
549:         if (isFullUnstaked) {
550:             delete _streamIDs[streamOwner][_streamID];
551:             delete _streamIDOwners[_streamID];
552:         } else {
553:             data.amount -= amount;
554:         }
555: 
556:         
557:         if (isFullUnstaked) {
558:             sablier.transferFrom({ from: address(this), to: streamOwner, tokenId: _streamID }); // <= FOUND
559:         }
560: 
561:         points.onUnstaked(msg.sender, amount);
562: 
563:         emit VestedUnstaked(streamOwner, epoch, amount, _streamID);
564:     }
```


</details>

## [Low-5] Arbitrary staking/deposit on a arbitrary token with an arbitrary amount has no checks to ensure token amount isn't type(uint256).max thus allowing wrong stake amount for certain tokens with custom logic such as cUSDCv3

### Resolution 
Certain tokens such as cUSDCv3 have transfer logic where when a transfer takes place their transfer functionality checks if the 'amount' to be transferred is type(uint256).max, if this is the case the balance of the sender is transferred. So if a user has a dust amount cUSDCv3 attempts to stake/deposit amount 'type(uint256).max'  in this protocol, the actual transfer amount will be procesed as the user's total balance of that token, not type(uint256).max. Thus the staking function will register/queue the stake as type(uint256).max but in actuality only cUSDCv3.balanceOf(msg.sender) will have been transferred. This can cause serious discrepancies with the protocols intended logic. To remedy this, there can be a check to prevent users from passing type(uint256).max as the stake/deposit amount. 

Num of instances: 3

### Findings 


<details><summary>Click to show findings</summary>

['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L368)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards { // <= FOUND
369:         
370:         if (_amount == 0) revert InvalidAmount();
371: 
372:         
373:         userData[msg.sender].unredeemedEpoch = currentEpoch;
374: 
375:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
376:         if (dr.epoch == 0) {
377:             dr.staked = _amount;
378:             dr.epoch = currentEpoch;
379:             _activeDeposits[msg.sender].add(currentEpoch);
380:         } else {
381:             dr.staked += _amount;
382:         }
383: 
384:         newStaked += _amount;
385: 
386:         
387:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
388:         points.onStaked(msg.sender, _amount);
389: 
390:         emit Staked(msg.sender, currentEpoch, _amount);
391:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L755)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin { // <= FOUND
756:         
757:         if (_amount == 0) revert InvalidAmount();
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
764: 
765:         _checkEpochRollover();
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```
['[143](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L143-L143)']
```solidity
143:     function bid(uint256 amount) external { // <= FOUND
144:         if (block.timestamp > auctionEndTime) {
145:             revert AuctionAlreadyEnded();
146:         }
147: 
148:         bids[msg.sender] = bids[msg.sender].add(amount);
149:         totalBids = totalBids.add(amount);
150: 
151:         fjordPoints.transferFrom(msg.sender, address(this), amount);
152:         emit BidAdded(msg.sender, amount);
153:     }
```


</details>

## [Low-6] Token supply should not be centralised at deployment

### Resolution 
Avoid minting tokens to a single address on deployment, rather have them distributed as intended within the constructor (i.e liquidity pools)

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[7](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordToken.sol#L7-L8)']
```solidity
7:     constructor() ERC20("Fjord Foundry", "FJO", 18) {
8:         _mint(msg.sender, 100_000_000 ether); // <= FOUND
9:     }
```


</details>

## [Low-7] Loss of precision

### Resolution 
Dividing by large numbers in Solidity can cause a loss of precision due to the language's inherent integer division behavior. Solidity does not support floating-point arithmetic, and as a result, division between integers yields an integer result, truncating any fractional part. When dividing by a large number, the resulting value may become significantly smaller, leading to a loss of precision, as the fractional part is discarded.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[330](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L330-L332)']
```solidity
330:     function getEpoch(uint256 _timestamp) public view returns (uint16) { // <= FOUND
331:         if (_timestamp < startTime) return 0;
332:         return uint16((_timestamp - startTime) / epochDuration) + 1; // <= FOUND
333:     }
```
['[775](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L775-L780)']
```solidity
775:     function calculateReward(uint256 _amount, uint16 _fromEpoch, uint16 _toEpoch)
776:         internal
777:         view
778:         returns (uint256 rewardAmount)
779:     {
780:         rewardAmount = // <= FOUND
781:             (_amount * (rewardPerToken[_toEpoch] - rewardPerToken[_fromEpoch])) / PRECISION_18;
782:     }
```


</details>

## [Low-8] Staking address can be changed

### Resolution 
The changeability of a staking address after it's set could put investors' rewards at risk. If the staking address were to be altered, staked funds and the corresponding rewards could be rerouted to an unintended recipient or be lost. Investors expecting returns on their stakes might not receive their due rewards. This unpredictability and lack of trust can deter potential and existing investors from participating in the staking process. Hence, to protect investor interests, ensure trust, and maintain a fair staking system, staking addresses should remain immutable once set, ensuring the rewards are distributed as per the original agreement.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner {
173:         if (_staking == address(0)) {
174:             revert InvalidAddress();
175:         }
176: 
177:         staking = _staking;
178:     }
```


</details>

## [Low-9] Constant decimal values

### Resolution 
The use of fixed decimal values such as 1e18 or 1e8 in Solidity contracts can lead to inaccuracies, bugs, and vulnerabilities, particularly when interacting with tokens having different decimal configurations. Not all ERC20 tokens follow the standard 18 decimal places, and assumptions about decimal places can lead to miscalculations.

Resolution: Always retrieve and use the `decimals()` function from the token contract itself when performing calculations involving token amounts. This ensures that your contract correctly handles tokens with any number of decimal places, mitigating the risk of numerical errors or under/overflows that could jeopardize contract integrity and user funds.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[85](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L85-L86)']
```solidity
85:     
86:     uint256 public constant PRECISION_18 = 1e18; // <= FOUND
```


</details>

## [Low-10] Events may be emitted out of order due to code not follow the best practice of check-effects-interaction

### Resolution 
The "check-effects-interaction" pattern also impacts event ordering. When a contract doesn't adhere to this pattern, events might be emitted in a sequence that doesn't reflect the actual logical flow of operations. This can cause confusion during event tracking, potentially leading to erroneous off-chain interpretations. To rectify this, always ensure that checks are performed first, state modifications come next, and interactions with external contracts or addresses are done last. This will ensure events are emitted in a logical, consistent manner, providing a clear and accurate chronological record of on-chain actions for off-chain systems and observers.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L65)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress); // <= FOUND
66:     }
```


</details>

## [Low-11] Critical functions should have a timelock

### Resolution 
Critical functions, especially those affecting protocol parameters or user funds, are potential points of failure or exploitation. To mitigate risks, incorporating a timelock on such functions can be beneficial. A timelock requires a waiting period between the time an action is initiated and when it's executed, giving stakeholders time to react, potentially vetoing malicious or erroneous changes. To implement, integrate a smart contract like OpenZeppelin's `TimelockController` or build a custom mechanism. This ensures governance decisions or administrative changes are transparent and allows for community or multi-signature interventions, enhancing protocol security and trustworthiness.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner  // <= FOUND
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner  // <= FOUND
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution  // <= FOUND
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner  // <= FOUND
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner  // <= FOUND
```


</details>

## [Low-12] Consider implementing two-step procedure for updating protocol addresses

### Resolution 
Implementing a two-step procedure for updating protocol addresses adds an extra layer of security. In such a system, the first step initiates the change, and the second step, after a predefined delay, confirms and finalizes it. This delay allows stakeholders or monitoring tools to observe and react to unintended or malicious changes. If an unauthorized change is detected, corrective actions can be taken before the change is finalized. To achieve this, introduce a "proposed address" state variable and a "delay period". Upon an update request, set the "proposed address". After the delay, if not contested, the main protocol address can be updated.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner { // <= FOUND
164:         if (_newOwner == address(0)) revert InvalidAddress();
165:         owner = _newOwner;
166:     }
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner { // <= FOUND
173:         if (_staking == address(0)) {
174:             revert InvalidAddress();
175:         }
176: 
177:         staking = _staking;
178:     }
```
['[347](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L347-L347)']
```solidity
347:     function setOwner(address _newOwner) external onlyOwner { // <= FOUND
348:         if (_newOwner == address(0)) revert InvalidZeroAddress();
349:         owner = _newOwner;
350:     }
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner { // <= FOUND
353:         if (_rewardAdmin == address(0)) revert InvalidZeroAddress();
354:         rewardAdmin = _rewardAdmin;
355:     }
```


</details>

## [Low-13] SafeTransferLib does not ensure that the token contract exists

### Resolution 
SafeTransferLib as similarly named function as OpenZepelins SafeERC20 module however it's functions such as safeTransferFrom don't check if the contract exists which can result in silent failures when performing such operations. As such it is recommended to perform a contract existence check beforehand. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[5](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L5-L5)']
```solidity
5: import { SafeTransferLib } from "solmate/utils/SafeTransferLib.sol"; // <= FOUND
```


</details>

## [Low-14] transfer will always revert as the IERC20 interface mismatch

### Resolution 
In Solidity, using the ERC20 transfer function can be problematic with tokens like USDT, which may not fully adhere to the standard interface, potentially causing transaction reverts. To avoid issues, it’s crucial to interact directly with the token's specific ABI rather than the generic IERC20 interface. Before integrating any token, thoroughly review its contract to ensure compatibility, especially for the transfer method. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L63)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```


</details>

## [Low-15] Constructors missing validation

### Resolution 
In Solidity, when values are being assigned in constructors to unsigned or integer variables, it's crucial to ensure the provided values adhere to the protocol's specific operational boundaries as laid out in the project specifications and documentation. If the constructors lack appropriate validation checks, there's a risk of setting state variables with values that could cause unexpected and potentially detrimental behavior within the contract's operations, violating the intended logic of the protocol. This can compromise the contract's security and impact the maintainability and reliability of the system. In order to avoid such issues, it is recommended to incorporate rigorous validation checks in constructors. These checks should align with the project's defined rules and constraints, making use of Solidity's built-in require function to enforce these conditions. If the validation checks fail, the require function will cause the transaction to revert, ensuring the integrity and adherence to the protocol's expected behavior.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[120](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L120-L136)']
```solidity
120:     constructor(
121:         address _fjordPoints,
122:         address _auctionToken,
123:         uint256 _biddingTime,
124:         uint256 _totalTokens
125:     ) {
126:         if (_fjordPoints == address(0)) {
127:             revert InvalidFjordPointsAddress();
128:         }
129:         if (_auctionToken == address(0)) {
130:             revert InvalidAuctionTokenAddress();
131:         }
132:         fjordPoints = ERC20Burnable(_fjordPoints);
133:         auctionToken = IERC20(_auctionToken);
134:         owner = msg.sender;
135:         auctionEndTime = block.timestamp.add(_biddingTime);
136:         totalTokens = _totalTokens; // <= FOUND
137:     }
```


</details>

## [Low-16] Return values not checked for OZ EnumerableSet add/remove functions

### Resolution 
In OpenZeppelin's EnumerableSet library, the `add` and `remove` functions return boolean values indicating success or failure. Not checking these return values can lead to unnoticed errors, especially in complex contract logic. It's a best practice to always check the return values of these functions to ensure that the intended modifications to the set were successful. Ignoring them could result in a false assumption of successful addition or removal, potentially leading to security flaws or logical errors in contract execution. Proper handling of these return values contributes to more robust and error-free smart contract code.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[35](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L35-L590)']
```solidity
35: contract FjordStaking is ISablierV2LockupRecipient { // <= FOUND
36:     
40:     using EnumerableSet for EnumerableSet.UintSet;
41:     using SafeTransferLib for ERC20;
42: 
379:             _activeDeposits[msg.sender].add(currentEpoch); // <= FOUND


424:             _activeDeposits[msg.sender].add(currentEpoch); // <= FOUND


484:             _activeDeposits[msg.sender].remove(_epoch); // <= FOUND


546:             _activeDeposits[streamOwner].remove(data.epoch); // <= FOUND


590:                 _activeDeposits[msg.sender].remove(epoch); // <= FOUND


```


</details>

## [Low-17] Functions calling contracts/addresses with transfer hooks are missing reentrancy guards

### Resolution 
While adherence to the check-effects-interaction pattern is commendable, the absence of a reentrancy guard in functions, especially where transfer hooks might be present, can expose the protocol users to risks of read-only reentrancies. Such reentrancy vulnerabilities can be exploited to execute malicious actions even without altering the contract state. Without a reentrancy guard, the only potential mitigation would be to blocklist the entire protocol - an extreme and disruptive measure. Therefore, incorporating a reentrancy guard into these functions is vital to bolster security, as it helps protect against both traditional reentrancy attacks and read-only reentrancies, ensuring robust and safe protocol operations.

Num of instances: 14

### Findings 


<details><summary>Click to show findings</summary>

['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L174)']
```solidity
159:     function unbid(uint256 amount) external { // <= FOUND
160:         if (block.timestamp > auctionEndTime) {
161:             revert AuctionAlreadyEnded();
162:         }
163: 
164:         uint256 userBids = bids[msg.sender];
165:         if (userBids == 0) {
166:             revert NoBidsToWithdraw();
167:         }
168:         if (amount > userBids) {
169:             revert InvalidUnbidAmount();
170:         }
171: 
172:         bids[msg.sender] = bids[msg.sender].sub(amount);
173:         totalBids = totalBids.sub(amount);
174:         fjordPoints.transfer(msg.sender, amount); // <= FOUND
175:         emit BidWithdrawn(msg.sender, amount);
176:     }
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L192)']
```solidity
181:     function auctionEnd() external { // <= FOUND
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded();
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled();
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) { // <= FOUND
193:             auctionToken.transfer(owner, totalTokens);
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[207](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L207-L220)']
```solidity
207:     function claimTokens() external { // <= FOUND
208:         if (!ended) {
209:             revert AuctionNotYetEnded();
210:         }
211: 
212:         uint256 userBids = bids[msg.sender];
213:         if (userBids == 0) {
214:             revert NoTokensToClaim();
215:         }
216: 
217:         uint256 claimable = userBids.mul(multiplier).div(PRECISION_18);
218:         bids[msg.sender] = 0;
219: 
220:         auctionToken.transfer(msg.sender, claimable); // <= FOUND
221:         emit TokensClaimed(msg.sender, claimable);
222:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L490)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount;
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total); // <= FOUND
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L600)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount); // <= FOUND
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L654)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L684)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     {
668:         ClaimReceipt memory cr = claimReceipts[msg.sender];
669: 
670:         
671:         if (cr.requestEpoch < 1) revert ClaimReceiptNotFound();
672:         
673:         if (currentEpoch - cr.requestEpoch <= claimCycle) revert CompleteRequestTooEarly();
674: 
675:         
676:         rewardAmount = cr.amount;
677: 
678:         userData[msg.sender].unclaimedRewards -= rewardAmount;
679: 
680:         totalRewards -= rewardAmount;
681:         delete claimReceipts[msg.sender];
682: 
683:         
684:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
685: 
686:         emit RewardClaimed(msg.sender, rewardAmount);
687:     }
```
['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L174)']
```solidity
159:     function unbid(uint256 amount) external {
160:         if (block.timestamp > auctionEndTime) {
161:             revert AuctionAlreadyEnded();
162:         }
163: 
164:         uint256 userBids = bids[msg.sender];
165:         if (userBids == 0) {
166:             revert NoBidsToWithdraw();
167:         }
168:         if (amount > userBids) {
169:             revert InvalidUnbidAmount();
170:         }
171: 
172:         bids[msg.sender] = bids[msg.sender].sub(amount);
173:         totalBids = totalBids.sub(amount);
174:         fjordPoints.transfer(msg.sender, amount); // <= FOUND
175:         emit BidWithdrawn(msg.sender, amount);
176:     }
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L193)']
```solidity
181:     function auctionEnd() external {
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded();
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled();
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) {
193:             auctionToken.transfer(owner, totalTokens); // <= FOUND
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[207](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L207-L220)']
```solidity
207:     function claimTokens() external {
208:         if (!ended) {
209:             revert AuctionNotYetEnded();
210:         }
211: 
212:         uint256 userBids = bids[msg.sender];
213:         if (userBids == 0) {
214:             revert NoTokensToClaim();
215:         }
216: 
217:         uint256 claimable = userBids.mul(multiplier).div(PRECISION_18);
218:         bids[msg.sender] = 0;
219: 
220:         auctionToken.transfer(msg.sender, claimable); // <= FOUND
221:         emit TokensClaimed(msg.sender, claimable);
222:     }
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L600)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount); // <= FOUND
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L490)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount;
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total); // <= FOUND
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L654)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L684)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     {
668:         ClaimReceipt memory cr = claimReceipts[msg.sender];
669: 
670:         
671:         if (cr.requestEpoch < 1) revert ClaimReceiptNotFound();
672:         
673:         if (currentEpoch - cr.requestEpoch <= claimCycle) revert CompleteRequestTooEarly();
674: 
675:         
676:         rewardAmount = cr.amount;
677: 
678:         userData[msg.sender].unclaimedRewards -= rewardAmount;
679: 
680:         totalRewards -= rewardAmount;
681:         delete claimReceipts[msg.sender];
682: 
683:         
684:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
685: 
686:         emit RewardClaimed(msg.sender, rewardAmount);
687:     }
```


</details>

## [Low-18] Missing events in functions that are either setters, privileged or voting related

### Resolution 
Sensitive setter functions in smart contracts often alter critical state variables. Without events emitted in these functions, external observers or dApps cannot easily track or react to these state changes. Missing events can obscure contract activity, hampering transparency and making integration more challenging. To resolve this, incorporate appropriate event emissions within these functions. Events offer an efficient way to log crucial changes, aiding in real-time tracking and post-transaction verification.

Num of instances: 7

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner 
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner 
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution 
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner 
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner 
```
['[357](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L357-L357)']
```solidity
357:     function addAuthorizedSablierSender(address _address) external onlyOwner 
```
['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L361)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner 
```


</details>

## [Low-19] Unsafe use of transfer()/transferFrom() with IERC20

### Resolution 
SafeTransfer should be used in place of Transfer for Solidity contracts to ensure robust security and error handling. Unlike the basic Transfer function, SafeTransfer incorporates safeguards against potential smart contract vulnerabilities, such as reentrancy attacks and unexpected token loss. By automatically validating the recipient's ability to receive tokens and reverting transactions in case of failures, 

Num of instances: 6

### Findings 


<details><summary>Click to show findings</summary>

['[143](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L143-L151)']
```solidity
143:     function bid(uint256 amount) external { // <= FOUND
144:         if (block.timestamp > auctionEndTime) {
145:             revert AuctionAlreadyEnded();
146:         }
147: 
148:         bids[msg.sender] = bids[msg.sender].add(amount);
149:         totalBids = totalBids.add(amount);
150: 
151:         fjordPoints.transferFrom(msg.sender, address(this), amount); // <= FOUND
152:         emit BidAdded(msg.sender, amount);
153:     }
```
['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L174)']
```solidity
159:     function unbid(uint256 amount) external { // <= FOUND
160:         if (block.timestamp > auctionEndTime) {
161:             revert AuctionAlreadyEnded();
162:         }
163: 
164:         uint256 userBids = bids[msg.sender];
165:         if (userBids == 0) {
166:             revert NoBidsToWithdraw();
167:         }
168:         if (amount > userBids) {
169:             revert InvalidUnbidAmount();
170:         }
171: 
172:         bids[msg.sender] = bids[msg.sender].sub(amount);
173:         totalBids = totalBids.sub(amount);
174:         fjordPoints.transfer(msg.sender, amount); // <= FOUND
175:         emit BidWithdrawn(msg.sender, amount);
176:     }
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L193)']
```solidity
181:     function auctionEnd() external { // <= FOUND
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded();
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled();
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) {
193:             auctionToken.transfer(owner, totalTokens); // <= FOUND
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[207](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L207-L220)']
```solidity
207:     function claimTokens() external { // <= FOUND
208:         if (!ended) {
209:             revert AuctionNotYetEnded();
210:         }
211: 
212:         uint256 userBids = bids[msg.sender];
213:         if (userBids == 0) {
214:             revert NoTokensToClaim();
215:         }
216: 
217:         uint256 claimable = userBids.mul(multiplier).div(PRECISION_18);
218:         bids[msg.sender] = 0;
219: 
220:         auctionToken.transfer(msg.sender, claimable); // <= FOUND
221:         emit TokensClaimed(msg.sender, claimable);
222:     }
```
['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L63)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L600)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount); // <= FOUND
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```


</details>

## [Low-20] Common tokens such as `WETH9` work differently on chains such a `Blast` which isn't taken into account during transfer calls.

### Resolution 
There is a difference on chains such as Blast on how WETH9 is implemented. On most chains the WETH9 contract contains handling for the case where src == msg.sender, however on chains such as Blast, Arbitrum and Fantom. This isn’t the case. Failing to take this discrepancy into account can results in the protocol not functioning as intended on these chains which can have drastic results. Particularly in cases where the contract interacts with it’s own WETH allowance through transferFrom calls, in such cases these can fail if the contract fails to approve itself to use it’s WETH balance which normally isn't done as most WETH contracts do not require approval for instances where src is msg.sender. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L63)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```


</details>

## [Low-21] SafeTransferLib does not ensure that the token contract exists

### Resolution 
SafeTransferLib as similarly named function as OpenZepelins SafeERC20 module however it's functions such as safeTransferFrom don't check if the contract exists which can result in silent failures when performing such operations. As such it is recommended to perform a contract existence check beforehand. 

Num of instances: 7

### Findings 


<details><summary>Click to show findings</summary>

['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L387)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards {
369:         
370:         if (_amount == 0) revert InvalidAmount();
371: 
372:         
373:         userData[msg.sender].unredeemedEpoch = currentEpoch;
374: 
375:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
376:         if (dr.epoch == 0) {
377:             dr.staked = _amount;
378:             dr.epoch = currentEpoch;
379:             _activeDeposits[msg.sender].add(currentEpoch);
380:         } else {
381:             dr.staked += _amount;
382:         }
383: 
384:         newStaked += _amount;
385: 
386:         
387:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount); // <= FOUND
388:         points.onStaked(msg.sender, _amount);
389: 
390:         emit Staked(msg.sender, currentEpoch, _amount);
391:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L763)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin {
756:         
757:         if (_amount == 0) revert InvalidAmount();
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount); // <= FOUND
764: 
765:         _checkEpochRollover();
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L490)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount;
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total); // <= FOUND
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L654)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L684)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     {
668:         ClaimReceipt memory cr = claimReceipts[msg.sender];
669: 
670:         
671:         if (cr.requestEpoch < 1) revert ClaimReceiptNotFound();
672:         
673:         if (currentEpoch - cr.requestEpoch <= claimCycle) revert CompleteRequestTooEarly();
674: 
675:         
676:         rewardAmount = cr.amount;
677: 
678:         userData[msg.sender].unclaimedRewards -= rewardAmount;
679: 
680:         totalRewards -= rewardAmount;
681:         delete claimReceipts[msg.sender];
682: 
683:         
684:         fjordToken.safeTransfer(msg.sender, rewardAmount); // <= FOUND
685: 
686:         emit RewardClaimed(msg.sender, rewardAmount);
687:     }
```
['[691](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L691-L699)']
```solidity
691:     function _checkEpochRollover() internal {
692:         uint16 latestEpoch = getEpoch(block.timestamp);
693: 
694:         if (latestEpoch > currentEpoch) {
695:             
696:             currentEpoch = latestEpoch;
697: 
698:             if (totalStaked > 0) {
699:                 uint256 currentBalance = fjordToken.balanceOf(address(this)); // <= FOUND
700: 
701:                 
702:                 uint256 pendingRewards = (currentBalance + totalVestedStaked + newVestedStaked)
703:                     - totalStaked - newStaked - totalRewards;
704:                 uint256 pendingRewardsPerToken = (pendingRewards * PRECISION_18) / totalStaked;
705:                 totalRewards += pendingRewards;
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
709:                 }
710:             } else {
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
714:                 }
715:             }
716: 
717:             totalStaked += newStaked;
718:             totalVestedStaked += newVestedStaked;
719:             newStaked = 0;
720:             newVestedStaked = 0;
721: 
722:             lastEpochRewarded = currentEpoch - 1;
723:         }
724:     }
```
['[5](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L5-L5)']
```solidity
5: import { SafeTransferLib } from "solmate/utils/SafeTransferLib.sol"; // <= FOUND
```


</details>

## [NonCritical-1] Consider using time variables when defining time related variables 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[250](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L250-L255)']
```solidity
250:     
255:     uint256 public constant epochDuration = 86_400 * 7;  // <= FOUND
```


</details>

## [NonCritical-2] Events regarding state variable changes should emit the previous state variable value

### Resolution 
Modify such events to contain the previous value of the state variable as demonstrated in the example below

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[119](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L119-L119)']
```solidity
119: event RewardPerTokenChanged(uint16 epoch, uint256 rewardPerToken);
```


</details>

## [NonCritical-3] In functions which accept an address as a parameter, there should be a zero address check to prevent bugs

### Resolution 
In smart contract development, especially with Solidity, it's crucial to validate inputs to functions. When a function accepts an Ethereum address as a parameter, implementing a zero address check (i.e., ensuring the address is not `0x0`) is a best practice to prevent potential bugs and vulnerabilities. The zero address (`0x0`) is a default value and generally indicates an uninitialized or invalid state. Passing the zero address to certain functions can lead to unintended behaviors, like funds getting locked permanently or transactions failing silently. By checking for and rejecting the zero address, developers can ensure that the function operates as intended and interacts only with valid Ethereum addresses. This check enhances the contract's robustness and security.

Num of instances: 10

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L52)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner 
```
['[197](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L197-L197)']
```solidity
197:     function onStaked(address user, uint256 amount)
198:         external
199:         onlyStaking
200:         checkDistribution
201:         updatePendingPoints(user)
202:     
```
['[214](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L214-L214)']
```solidity
214:     function onUnstaked(address user, uint256 amount)
215:         external
216:         onlyStaking
217:         checkDistribution
218:         updatePendingPoints(user)
219:     
```
['[335](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L335-L335)']
```solidity
335:     function getActiveDeposits(address _user) public view returns (uint256[] memory) 
```
['[339](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L339-L339)']
```solidity
339:     function getStreamData(address _user, uint256 _streamID) public view returns (NFTData memory) 
```
['[357](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L357-L357)']
```solidity
357:     function addAuthorizedSablierSender(address _address) external onlyOwner 
```
['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L361)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner 
```
['[521](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L521-L521)']
```solidity
521:     function _unstakeVested(address streamOwner, uint256 _streamID, uint256 amount) internal 
```
['[729](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L729-L729)']
```solidity
729:     function _redeem(address sender) internal 
```
['[792](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L792-L792)']
```solidity
792:     function onStreamWithdrawn(
793:         uint256, 
794:         address, 
795:         address, 
796:         uint128 
797:     ) external override onlySablier 
```


</details>

## [NonCritical-4] Default int values are manually set

### Resolution 
In instances where a new variable is defined, there is no need to set it to it's default value.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579:         for (uint16 i = 0; i < activeDeposits.length; i++) { // <= FOUND
```


</details>

## [NonCritical-5] Revert statements within external and public functions can be used to perform DOS attacks

### Resolution 
In Solidity, 'revert' statements are used to undo changes and throw an exception when certain conditions are not met. However, in public and external functions, improper use of `revert` can be exploited for Denial of Service (DoS) attacks. An attacker can intentionally trigger these 'revert' conditions, causing legitimate transactions to consistently fail. For example, if a function relies on specific conditions from user input or contract state, an attacker could manipulate these to continually force reverts, blocking the function's execution. Therefore, it's crucial to design contract logic to handle exceptions properly and avoid scenarios where `revert` can be predictably triggered by malicious actors. This includes careful input validation and considering alternative design patterns that are less susceptible to such abuses.

Num of instances: 19

### Findings 


<details><summary>Click to show findings</summary>

['[143](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L143-L145)']
```solidity
143:     function bid(uint256 amount) external {
144:         if (block.timestamp > auctionEndTime) {
145:             revert AuctionAlreadyEnded(); // <= FOUND
146:         }
147: 
148:         bids[msg.sender] = bids[msg.sender].add(amount);
149:         totalBids = totalBids.add(amount);
150: 
151:         fjordPoints.transferFrom(msg.sender, address(this), amount);
152:         emit BidAdded(msg.sender, amount);
153:     }
```
['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L169)']
```solidity
159:     function unbid(uint256 amount) external {
160:         if (block.timestamp > auctionEndTime) {
161:             revert AuctionAlreadyEnded(); // <= FOUND
162:         }
163: 
164:         uint256 userBids = bids[msg.sender];
165:         if (userBids == 0) {
166:             revert NoBidsToWithdraw(); // <= FOUND
167:         }
168:         if (amount > userBids) {
169:             revert InvalidUnbidAmount(); // <= FOUND
170:         }
171: 
172:         bids[msg.sender] = bids[msg.sender].sub(amount);
173:         totalBids = totalBids.sub(amount);
174:         fjordPoints.transfer(msg.sender, amount);
175:         emit BidWithdrawn(msg.sender, amount);
176:     }
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L186)']
```solidity
181:     function auctionEnd() external {
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded(); // <= FOUND
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled(); // <= FOUND
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) {
193:             auctionToken.transfer(owner, totalTokens);
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[207](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L207-L214)']
```solidity
207:     function claimTokens() external {
208:         if (!ended) {
209:             revert AuctionNotYetEnded(); // <= FOUND
210:         }
211: 
212:         uint256 userBids = bids[msg.sender];
213:         if (userBids == 0) {
214:             revert NoTokensToClaim(); // <= FOUND
215:         }
216: 
217:         uint256 claimable = userBids.mul(multiplier).div(PRECISION_18);
218:         bids[msg.sender] = 0;
219: 
220:         auctionToken.transfer(msg.sender, claimable);
221:         emit TokensClaimed(msg.sender, claimable);
222:     }
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L164)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner {
164:         if (_newOwner == address(0)) revert InvalidAddress(); // <= FOUND
165:         owner = _newOwner;
166:     }
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L174)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner {
173:         if (_staking == address(0)) {
174:             revert InvalidAddress(); // <= FOUND
175:         }
176: 
177:         staking = _staking;
178:     }
```
['[214](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L214-L222)']
```solidity
214:     function onUnstaked(address user, uint256 amount)
215:         external
216:         onlyStaking
217:         checkDistribution
218:         updatePendingPoints(user)
219:     {
220:         UserInfo storage userInfo = users[user];
221:         if (amount > userInfo.stakedAmount) {
222:             revert UnstakingAmountExceedsStakedAmount(); // <= FOUND
223:         }
224:         userInfo.stakedAmount = userInfo.stakedAmount.sub(amount);
225:         totalStaked = totalStaked.sub(amount);
226:         emit Unstaked(user, amount);
227:     }
```
['[347](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L347-L348)']
```solidity
347:     function setOwner(address _newOwner) external onlyOwner {
348:         if (_newOwner == address(0)) revert InvalidZeroAddress(); // <= FOUND
349:         owner = _newOwner;
350:     }
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L353)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner {
353:         if (_rewardAdmin == address(0)) revert InvalidZeroAddress(); // <= FOUND
354:         rewardAdmin = _rewardAdmin;
355:     }
```
['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L370)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards {
369:         
370:         if (_amount == 0) revert InvalidAmount(); // <= FOUND
371: 
372:         
373:         userData[msg.sender].unredeemedEpoch = currentEpoch;
374: 
375:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
376:         if (dr.epoch == 0) {
377:             dr.staked = _amount;
378:             dr.epoch = currentEpoch;
379:             _activeDeposits[msg.sender].add(currentEpoch);
380:         } else {
381:             dr.staked += _amount;
382:         }
383: 
384:         newStaked += _amount;
385: 
386:         
387:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
388:         points.onStaked(msg.sender, _amount);
389: 
390:         emit Staked(msg.sender, currentEpoch, _amount);
391:     }
```
['[397](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L397-L412)']
```solidity
397:     function stakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards {
398:         
399:         if (!sablier.isStream(_streamID)) revert NotAStream(); // <= FOUND
400:         if (sablier.isCold(_streamID)) revert NotAWarmStream(); // <= FOUND
401: 
402:         
403:         if (!authorizedSablierSenders[sablier.getSender(_streamID)]) {
404:             revert StreamNotSupported(); // <= FOUND
405:         }
406:         if (address(sablier.getAsset(_streamID)) != address(fjordToken)) revert InvalidAsset(); // <= FOUND
407: 
408:         uint128 depositedAmount = sablier.getDepositedAmount(_streamID);
409:         uint128 withdrawnAmount = sablier.getWithdrawnAmount(_streamID);
410:         uint128 refundedAmount = sablier.getRefundedAmount(_streamID);
411: 
412:         if (depositedAmount - (withdrawnAmount + refundedAmount) <= 0) revert InvalidAmount(); // <= FOUND
413: 
414:         uint256 _amount = depositedAmount - (withdrawnAmount + refundedAmount);
415: 
416:         
417:         userData[msg.sender].unredeemedEpoch = currentEpoch;
418: 
419:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
420:         if (dr.epoch == 0) {
421:             dr.vestedStaked = _amount;
422:             dr.epoch = currentEpoch;
423: 
424:             _activeDeposits[msg.sender].add(currentEpoch);
425:         } else {
426:             dr.vestedStaked += _amount;
427:         }
428: 
429:         _streamIDs[msg.sender][_streamID] = NFTData({ epoch: currentEpoch, amount: _amount });
430:         _streamIDOwners[_streamID] = msg.sender;
431:         newStaked += _amount;
432:         newVestedStaked += _amount;
433: 
434:         
435:         sablier.transferFrom({ from: msg.sender, to: address(this), tokenId: _streamID });
436:         points.onStaked(msg.sender, _amount);
437: 
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount);
439:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L465)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount(); // <= FOUND
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound(); // <= FOUND
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit(); // <= FOUND
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly(); // <= FOUND
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount;
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total);
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[502](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L502-L514)']
```solidity
502:     function unstakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards {
503:         
504:         NFTData memory data = _streamIDs[msg.sender][_streamID];
505:         DepositReceipt memory dr = deposits[msg.sender][data.epoch];
506: 
507:         if (data.epoch == 0 || data.amount == 0 || dr.vestedStaked == 0 || dr.epoch == 0) {
508:             revert DepositNotFound(); // <= FOUND
509:         }
510: 
511:         
512:         if (currentEpoch != data.epoch) {
513:             
514:             if (currentEpoch - data.epoch <= lockCycle) revert UnstakeEarly(); // <= FOUND
515:         }
516: 
517:         _unstakeVested(msg.sender, _streamID, data.amount);
518:     }
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L577)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit(); // <= FOUND
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount);
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L632)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly(); // <= FOUND
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim(); // <= FOUND
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount);
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L673)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     {
668:         ClaimReceipt memory cr = claimReceipts[msg.sender];
669: 
670:         
671:         if (cr.requestEpoch < 1) revert ClaimReceiptNotFound(); // <= FOUND
672:         
673:         if (currentEpoch - cr.requestEpoch <= claimCycle) revert CompleteRequestTooEarly(); // <= FOUND
674: 
675:         
676:         rewardAmount = cr.amount;
677: 
678:         userData[msg.sender].unclaimedRewards -= rewardAmount;
679: 
680:         totalRewards -= rewardAmount;
681:         delete claimReceipts[msg.sender];
682: 
683:         
684:         fjordToken.safeTransfer(msg.sender, rewardAmount);
685: 
686:         emit RewardClaimed(msg.sender, rewardAmount);
687:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L757)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin {
756:         
757:         if (_amount == 0) revert InvalidAmount(); // <= FOUND
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
764: 
765:         _checkEpochRollover();
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```
['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L831)']
```solidity
823:     function onStreamCanceled(
824:         uint256 streamId,
825:         address sender,
826:         uint128 senderAmount,
827:         uint128 
828:     ) external override onlySablier checkEpochRollover {
829:         address streamOwner = _streamIDOwners[streamId];
830: 
831:         if (streamOwner == address(0)) revert StreamOwnerNotFound(); // <= FOUND
832: 
833:         _redeem(streamOwner);
834: 
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId];
836: 
837:         uint256 amount =
838:             uint256(senderAmount) > nftData.amount ? nftData.amount : uint256(senderAmount);
839: 
840:         _unstakeVested(streamOwner, streamId, amount);
841: 
842:         emit SablierCanceled(streamOwner, streamId, sender, amount);
843:     }
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L186)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution {
185:         if (_points == 0) {
186:             revert(); // <= FOUND
187:         }
188: 
189:         pointsPerEpoch = _points;
190:     }
```


</details>

## [NonCritical-6] Functions which are either private or internal should have a preceding _ in their name

### Resolution 
Add a preceding underscore to the function name, take care to refactor where there functions are called

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[775](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L775-L775)']
```solidity
775:     function calculateReward(uint256 _amount, uint16 _fromEpoch, uint16 _toEpoch)
776:         internal
777:         view
778:         returns (uint256 rewardAmount)
779:     
```


</details>

## [NonCritical-7] Contract lines should not be longer than 120 characters for readability

### Resolution 
Consider spreading these lines over multiple lines to aid in readability and the support of VIM users everywhere.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[23](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L23-L23)']
```solidity
23:      * @notice Thrown when a distribution attempt is made before the allowed time (e.g., before the epoch duration has passed). // <= FOUND
```


</details>

## [NonCritical-8] Specific imports should be used where possible so only used code is imported

### Resolution 
In many cases only some functionality is used from an import. In such cases it makes more sense to use {} to specify what to import and thus save gas whilst improving readability

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[4](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L4-L4)']
```solidity
4: import "./FjordAuction.sol";
```
['[6](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L6-L6)']
```solidity
6: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
```


</details>

## [NonCritical-9] Not all event definitions are utilizing indexed variables.

### Resolution 
Try to index as much as three variables in event declarations as this is more gas efficient when done on value type variables (uint, address etc) however not for bytes and string variables 

Num of instances: 20

### Findings 


<details><summary>Click to show findings</summary>

['[91](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L91-L91)']
```solidity
91: event AuctionEnded(uint256 totalBids, uint256 totalTokens); // <= FOUND
```
['[98](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L98-L98)']
```solidity
98: event TokensClaimed(address indexed bidder, uint256 amount); // <= FOUND
```
['[105](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L105-L105)']
```solidity
105: event BidAdded(address indexed bidder, uint256 amount); // <= FOUND
```
['[112](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L112-L112)']
```solidity
112: event BidWithdrawn(address indexed bidder, uint256 amount); // <= FOUND
```
['[92](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L92-L92)']
```solidity
92: event Staked(address indexed user, uint256 amount); // <= FOUND
```
['[51](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L51-L51)']
```solidity
51: event Staked(address indexed user, uint16 indexed epoch, uint256 amount); // <= FOUND
```
['[99](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L99-L99)']
```solidity
99: event Unstaked(address indexed user, uint256 amount); // <= FOUND
```
['[88](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L88-L88)']
```solidity
88: event Unstaked(address indexed user, uint16 indexed epoch, uint256 stakedAmount); // <= FOUND
```
['[106](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L106-L106)']
```solidity
106: event PointsDistributed(uint256 points, uint256 pointsPerToken); // <= FOUND
```
['[113](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L113-L113)']
```solidity
113: event PointsClaimed(address indexed user, uint256 amount); // <= FOUND
```
['[65](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L65-L65)']
```solidity
65: event RewardAdded(uint16 indexed epoch, address rewardAdmin, uint256 amount); // <= FOUND
```
['[70](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L70-L70)']
```solidity
70: event RewardClaimed(address indexed user, uint256 amount); // <= FOUND
```
['[76](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L76-L76)']
```solidity
76: event EarlyRewardClaimed(address indexed user, uint256 rewardAmount, uint256 penaltyAmount); // <= FOUND
```
['[82](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L82-L82)']
```solidity
82: event ClaimedAll(address indexed user, uint256 totalRewardAmount, uint256 totalPenaltyAmount); // <= FOUND
```
['[95](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L95-L95)']
```solidity
95: event VestedUnstaked( // <= FOUND
96:         address indexed user, uint16 indexed epoch, uint256 stakedAmount, uint256 streamID
97:     );
```
['[104](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L104-L104)']
```solidity
104: event UnstakedAll( // <= FOUND
105:         address indexed user,
106:         uint256 totalStakedAmount,
107:         uint256[] activeDepositsBefore,
108:         uint256[] activeDepositsAfter
109:     );
```
['[114](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L114-L114)']
```solidity
114: event ClaimReceiptCreated(address indexed user, uint16 requestEpoch); // <= FOUND
```
['[119](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L119-L119)']
```solidity
119: event RewardPerTokenChanged(uint16 epoch, uint256 rewardPerToken); // <= FOUND
```
['[126](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L126-L126)']
```solidity
126: event SablierWithdrawn(address indexed user, uint256 streamID, address caller, uint256 amount); // <= FOUND
```
['[133](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L133-L133)']
```solidity
133: event SablierCanceled(address indexed user, uint256 streamID, address caller, uint256 amount); // <= FOUND
```


</details>

## [NonCritical-10] Contracts should have all public/external functions exposed by interfaces

### Resolution 
Contracts should expose all public and external functions through interfaces. This practice ensures a clear and consistent definition of how the contract can be interacted with, promoting better transparency and integration.

Num of instances: 28

### Findings 


<details><summary>Click to show findings</summary>

['[143](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L143-L143)']
```solidity
143:     function bid(uint256 amount) external 
```
['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L159)']
```solidity
159:     function unbid(uint256 amount) external 
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L181)']
```solidity
181:     function auctionEnd() external 
```
['[207](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L207-L207)']
```solidity
207:     function claimTokens() external 
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner 
```
['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L52)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner 
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner 
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution 
```
['[197](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L197-L197)']
```solidity
197:     function onStaked(address user, uint256 amount)
198:         external
199:         onlyStaking
200:         checkDistribution
201:         updatePendingPoints(user)
202:     
```
['[214](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L214-L214)']
```solidity
214:     function onUnstaked(address user, uint256 amount)
215:         external
216:         onlyStaking
217:         checkDistribution
218:         updatePendingPoints(user)
219:     
```
['[253](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L253-L253)']
```solidity
253:     function claimPoints() external checkDistribution updatePendingPoints(msg.sender) 
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner 
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner 
```
['[357](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L357-L357)']
```solidity
357:     function addAuthorizedSablierSender(address _address) external onlyOwner 
```
['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L361)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner 
```
['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L368)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards 
```
['[397](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L397-L397)']
```solidity
397:     function stakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards 
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L449)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     
```
['[502](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L502-L502)']
```solidity
502:     function unstakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards 
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L570)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L616)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L662)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L755)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin 
```
['[232](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L232-L232)']
```solidity
232:     function distributePoints() public 
```
['[330](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L330-L330)']
```solidity
330:     function getEpoch(uint256 _timestamp) public view returns (uint16) 
```
['[335](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L335-L335)']
```solidity
335:     function getActiveDeposits(address _user) public view returns (uint256[] memory) 
```
['[339](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L339-L339)']
```solidity
339:     function getStreamData(address _user, uint256 _streamID) public view returns (NFTData memory) 
```
['[343](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L343-L343)']
```solidity
343:     function getStreamOwner(uint256 _streamID) public view returns (address) 
```


</details>

## [NonCritical-11] Functions within contracts are not ordered according to the solidity style guide

### Resolution 
The following order should be used within contracts

constructor

receive function (if exists)

fallback function (if exists)

external

public

internal

private

Rearrange the contract functions and contructors to fit this ordering

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[14](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L14-L14)']
```solidity
14: contract FjordPoints is ERC20, ERC20Burnable, IFjordPoints  // <= FOUND
```
['[35](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L35-L35)']
```solidity
35: contract FjordStaking is ISablierV2LockupRecipient  // <= FOUND
```


</details>

## [NonCritical-12] Emits without msg.sender parameter

### Resolution 
In Solidity, when `msg.sender` plays a crucial role in a function's logic, it's important for transparency and auditability that any events emitted by this function include `msg.sender` as a parameter. This practice enhances the traceability and accountability of transactions, allowing users and external observers to easily track who initiated a particular action. Including `msg.sender` in event logs helps in creating a clear and verifiable record of interactions with the contract, thereby increasing user trust and facilitating easier debugging and analysis of contract behavior. It's a key aspect of writing clear, transparent, and user-friendly smart contracts.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L65)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress); // <= FOUND
66:     }
```
['[521](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L521-L563)']
```solidity
521:     function _unstakeVested(address streamOwner, uint256 _streamID, uint256 amount) internal {
522:         NFTData storage data = _streamIDs[streamOwner][_streamID];
523:         DepositReceipt storage dr = deposits[streamOwner][data.epoch];
524:         if (amount > data.amount) revert InvalidAmount();
525: 
526:         bool isFullUnstaked = data.amount == amount;
527:         uint16 epoch = data.epoch;
528: 
529:         dr.vestedStaked -= amount;
530:         if (currentEpoch != data.epoch) {
531:             totalStaked -= amount;
532:             totalVestedStaked -= amount;
533:             userData[streamOwner].totalStaked -= amount;
534:         } else {
535:             
536:             newStaked -= amount;
537:             newVestedStaked -= amount;
538:         }
539: 
540:         if (dr.vestedStaked == 0 && dr.staked == 0) {
541:             
542:             if (userData[streamOwner].unredeemedEpoch == currentEpoch) {
543:                 userData[streamOwner].unredeemedEpoch = 0;
544:             }
545:             delete deposits[streamOwner][data.epoch];
546:             _activeDeposits[streamOwner].remove(data.epoch);
547:         }
548:         
549:         if (isFullUnstaked) {
550:             delete _streamIDs[streamOwner][_streamID];
551:             delete _streamIDOwners[_streamID];
552:         } else {
553:             data.amount -= amount;
554:         }
555: 
556:         
557:         if (isFullUnstaked) {
558:             sablier.transferFrom({ from: address(this), to: streamOwner, tokenId: _streamID });
559:         }
560: 
561:         points.onUnstaked(msg.sender, amount); // <= FOUND
562: 
563:         emit VestedUnstaked(streamOwner, epoch, amount, _streamID); // <= FOUND
564:     }
```


</details>

## [NonCritical-13] A function which defines named returns in it's declaration doesn't need to use return

### Resolution 
Refacter the code to assign to the named return variables rather than using a return statement

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L648)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0); // <= FOUND
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0); // <= FOUND
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount);
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```


</details>

## [NonCritical-14] Constants should be on the left side of the comparison

### Resolution 
Putting constants on the left side of a comparison operator like `==` or `<` is a best practice known as "Yoda conditions", which can help prevent accidental assignment instead of comparison. In some programming languages, if a variable is mistakenly put on the left with a single `=` instead of `==`, it assigns the constant's value to the variable without any compiler error. However, doing this with the constant on the left would generate an error, as constants cannot be assigned values. Although Solidity's static typing system prevents accidental assignments within conditionals, adopting this practice enhances code readability and consistency, especially when developers are working across multiple languages that support this convention.

Num of instances: 12

### Findings 


<details><summary>Click to show findings</summary>

['[165](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L165-L165)']
```solidity
165:         if (userBids == 0)  // <= FOUND
```
['[192](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L192-L192)']
```solidity
192:         if (totalBids == 0)  // <= FOUND
```
['[165](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L165-L165)']
```solidity
165:         if (userBids == 0)  // <= FOUND
```
['[185](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L185-L185)']
```solidity
185:        if (_points == 0)  // <= FOUND
```
['[237](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L237-L237)']
```solidity
237:         if (totalStaked == 0)  // <= FOUND
```
['[376](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L376-L376)']
```solidity
376:         if (dr.epoch == 0)  // <= FOUND
```
['[376](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L376-L376)']
```solidity
376:         if (dr.epoch == 0)  // <= FOUND
```
['[507](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L507-L507)']
```solidity
507:         if (data.epoch == 0 || data.amount == 0 || dr.vestedStaked == 0 || dr.epoch == 0)  // <= FOUND
```
['[478](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L478-L478)']
```solidity
478:         if (dr.staked == 0 && dr.vestedStaked == 0)  // <= FOUND
```
['[540](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L540-L540)']
```solidity
540:         if (dr.vestedStaked == 0 && dr.staked == 0)  // <= FOUND
```
['[256](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L256-L256)']
```solidity
256:         if (pointsToClaim > 0)  // <= FOUND
```
['[737](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L737-L737)']
```solidity
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch)  // <= FOUND
```


</details>

## [NonCritical-15] Both immutable and constant state variables should be CONSTANT_CASE

### Resolution 
Make found instants CAPITAL_CASE

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[250](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L250-L250)']
```solidity
250: uint256 public constant epochDuration = 86_400 * 7;  // <= FOUND
```
['[259](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L259-L259)']
```solidity
259: uint8 public constant claimCycle = 3; // <= FOUND
```
['[265](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L265-L265)']
```solidity
265: uint256 public immutable startTime; // <= FOUND
```
['[253](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L253-L253)']
```solidity
253: uint8 public constant lockCycle = 6; // <= FOUND
```
['[262](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L262-L262)']
```solidity
262: ERC20 public immutable fjordToken; // <= FOUND
```


</details>

## [NonCritical-16] Use of non-named numeric constants

### Resolution 
Magic numbers should be avoided in Solidity code to enhance readability, maintainability, and reduce the likelihood of errors. Magic numbers are hard-coded values with no clear meaning or context, which can create confusion and make the code harder to understand for developers. Using well-defined constants or variables with descriptive names instead of magic numbers not only clarifies the purpose and significance of the value but also simplifies code updates and modifications.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[627](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L627-L631)']
```solidity
627:         
628:         
629:         if (
630:             claimReceipts[msg.sender].requestEpoch > 0
631:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1 // <= FOUND
632:         ) revert ClaimTooEarly();
```
['[742](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L742-L744)']
```solidity
742:             
743:             ud.unclaimedRewards += calculateReward(
744:                 deposit.staked + deposit.vestedStaked, ud.unredeemedEpoch, currentEpoch - 1 // <= FOUND
745:             );
```
['[8](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordToken.sol#L8-L8)']
```solidity
8:         _mint(msg.sender, 100_000_000 ether); // <= FOUND
```
['[645](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L645-L645)']
```solidity
645:         penaltyAmount = rewardAmount / 2; // <= FOUND
```


</details>

## [NonCritical-17] Unused errors present

### Resolution 
If these serve no purpose, they should be safely removed

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[25](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L25-L25)']
```solidity
25: error DistributionNotAllowedYet(); // <= FOUND
```
['[40](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L40-L40)']
```solidity
40: error TotalStakedAmountZero(); // <= FOUND
```


</details>

## [NonCritical-18] Empty bytes check is missing

### Resolution 
When developing smart contracts in Solidity, it's crucial to validate the inputs of your functions. This includes ensuring that the bytes parameters are not empty, especially when they represent crucial data such as addresses, identifiers, or raw data that the contract needs to process.

Missing empty bytes checks can lead to unexpected behaviour in your contract. For instance, certain operations might fail, produce incorrect results, or consume unnecessary gas when performed with empty bytes. Moreover, missing input validation can potentially expose your contract to malicious activity, including exploitation of unhandled edge cases.

To mitigate these issues, always validate that bytes parameters are not empty when the logic of your contract requires it.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L52)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens);
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```


</details>

## [NonCritical-19] Cyclomatic complexity in functions

### Resolution 
Cyclomatic complexity is a software metric used to measure the complexity of a program. It quantifies the number of linearly independent paths through a program's source code, giving an idea of how complex the control flow is. High cyclomatic complexity may indicate a higher risk of defects and can make the code harder to understand, test, and maintain. It often suggests that a function or method is trying to do too much, and a refactor might be needed. By breaking down complex functions into smaller, more focused pieces, you can improve readability, ease of testing, and overall maintainability.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[159](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L159-L159)']
```solidity
159:     function unbid(uint256 amount) external { // <= FOUND
160:         if (block.timestamp > auctionEndTime) {
161:             revert AuctionAlreadyEnded();
162:         }
163: 
164:         uint256 userBids = bids[msg.sender];
165:         if (userBids == 0) {
166:             revert NoBidsToWithdraw();
167:         }
168:         if (amount > userBids) {
169:             revert InvalidUnbidAmount();
170:         }
171: 
172:         bids[msg.sender] = bids[msg.sender].sub(amount);
173:         totalBids = totalBids.sub(amount);
174:         fjordPoints.transfer(msg.sender, amount);
175:         emit BidWithdrawn(msg.sender, amount);
176:     }
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L181-L181)']
```solidity
181:     function auctionEnd() external { // <= FOUND
182:         if (block.timestamp < auctionEndTime) {
183:             revert AuctionNotYetEnded();
184:         }
185:         if (ended) {
186:             revert AuctionEndAlreadyCalled();
187:         }
188: 
189:         ended = true;
190:         emit AuctionEnded(totalBids, totalTokens);
191: 
192:         if (totalBids == 0) {
193:             auctionToken.transfer(owner, totalTokens);
194:             return;
195:         }
196: 
197:         multiplier = totalTokens.mul(PRECISION_18).div(totalBids);
198: 
199:         
200:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this));
201:         fjordPoints.burn(pointsToBurn);
202:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L449)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount;
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total);
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[521](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L521-L521)']
```solidity
521:     function _unstakeVested(address streamOwner, uint256 _streamID, uint256 amount) internal { // <= FOUND
522:         NFTData storage data = _streamIDs[streamOwner][_streamID];
523:         DepositReceipt storage dr = deposits[streamOwner][data.epoch];
524:         if (amount > data.amount) revert InvalidAmount();
525: 
526:         bool isFullUnstaked = data.amount == amount;
527:         uint16 epoch = data.epoch;
528: 
529:         dr.vestedStaked -= amount;
530:         if (currentEpoch != data.epoch) {
531:             totalStaked -= amount;
532:             totalVestedStaked -= amount;
533:             userData[streamOwner].totalStaked -= amount;
534:         } else {
535:             
536:             newStaked -= amount;
537:             newVestedStaked -= amount;
538:         }
539: 
540:         if (dr.vestedStaked == 0 && dr.staked == 0) {
541:             
542:             if (userData[streamOwner].unredeemedEpoch == currentEpoch) {
543:                 userData[streamOwner].unredeemedEpoch = 0;
544:             }
545:             delete deposits[streamOwner][data.epoch];
546:             _activeDeposits[streamOwner].remove(data.epoch);
547:         }
548:         
549:         if (isFullUnstaked) {
550:             delete _streamIDs[streamOwner][_streamID];
551:             delete _streamIDOwners[_streamID];
552:         } else {
553:             data.amount -= amount;
554:         }
555: 
556:         
557:         if (isFullUnstaked) {
558:             sablier.transferFrom({ from: address(this), to: streamOwner, tokenId: _streamID });
559:         }
560: 
561:         points.onUnstaked(msg.sender, amount);
562: 
563:         emit VestedUnstaked(streamOwner, epoch, amount, _streamID);
564:     }
```


</details>

## [NonCritical-20] Unused events present

### Resolution 
If these serve no purpose, they should be safely removed

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[82](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L82-L82)']
```solidity
82: event ClaimedAll(address indexed user, uint256 totalRewardAmount, uint256 totalPenaltyAmount); // <= FOUND
```
['[126](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L126-L126)']
```solidity
126: event SablierWithdrawn(address indexed user, uint256 streamID, address caller, uint256 amount); // <= FOUND
```


</details>

## [NonCritical-21] Missing events in sensitive functions

### Resolution 
Sensitive setter functions in smart contracts often alter critical state variables. Without events emitted in these functions, external observers or dApps cannot easily track or react to these state changes. Missing events can obscure contract activity, hampering transparency and making integration more challenging. To resolve this, incorporate appropriate event emissions within these functions. Events offer an efficient way to log crucial changes, aiding in real-time tracking and post-transaction verification.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner { // <= FOUND
164:         if (_newOwner == address(0)) revert InvalidAddress();
165:         owner = _newOwner;
166:     }
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner { // <= FOUND
173:         if (_staking == address(0)) {
174:             revert InvalidAddress();
175:         }
176: 
177:         staking = _staking;
178:     }
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution { // <= FOUND
185:         if (_points == 0) {
186:             revert();
187:         }
188: 
189:         pointsPerEpoch = _points;
190:     }
```
['[347](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L347-L347)']
```solidity
347:     function setOwner(address _newOwner) external onlyOwner { // <= FOUND
348:         if (_newOwner == address(0)) revert InvalidZeroAddress();
349:         owner = _newOwner;
350:     }
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner { // <= FOUND
353:         if (_rewardAdmin == address(0)) revert InvalidZeroAddress();
354:         rewardAdmin = _rewardAdmin;
355:     }
```


</details>

## [NonCritical-22] A event should be emitted if a non immutable state variable is set in a constructor

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[120](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L120-L132)']
```solidity
120:     constructor(
121:         address _fjordPoints,
122:         address _auctionToken,
123:         uint256 _biddingTime,
124:         uint256 _totalTokens
125:     ) {
126:         if (_fjordPoints == address(0)) {
127:             revert InvalidFjordPointsAddress();
128:         }
129:         if (_auctionToken == address(0)) {
130:             revert InvalidAuctionTokenAddress();
131:         }
132:         fjordPoints = ERC20Burnable(_fjordPoints); // <= FOUND
133:         auctionToken = IERC20(_auctionToken); // <= FOUND
134:         owner = msg.sender; // <= FOUND
135:         auctionEndTime = block.timestamp.add(_biddingTime); // <= FOUND
136:         totalTokens = _totalTokens; // <= FOUND
137:     }
```
['[24](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L24-L27)']
```solidity
24:     constructor(address _fjordPoints) {
25:         if (_fjordPoints == address(0)) revert InvalidAddress();
26: 
27:         fjordPoints = _fjordPoints; // <= FOUND
28:         owner = msg.sender; // <= FOUND
29:     }
```
['[118](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L118-L121)']
```solidity
118:     constructor() ERC20("BjordBoint", "BJB") {
119:         owner = msg.sender; // <= FOUND
120:         lastDistribution = block.timestamp; // <= FOUND
121:         pointsPerEpoch = 100 ether; // <= FOUND
122:     }
```
['[281](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L281-L297)']
```solidity
281:     constructor(
282:         address _fjordToken,
283:         address _rewardAdmin,
284:         address _sablier,
285:         address _authorizedSablierSender,
286:         address _fjordPoints
287:     ) {
288:         if (
289:             _rewardAdmin == address(0) || _sablier == address(0) || _fjordToken == address(0)
290:                 || _fjordPoints == address(0)
291:         ) revert InvalidZeroAddress();
292: 
293:         startTime = block.timestamp;
294:         owner = msg.sender; // <= FOUND
295:         fjordToken = ERC20(_fjordToken);
296:         currentEpoch = 1; // <= FOUND
297:         rewardAdmin = _rewardAdmin; // <= FOUND
298:         sablier = ISablierV2Lockup(_sablier); // <= FOUND
299:         points = IFjordPoints(_fjordPoints); // <= FOUND
300:         if (_authorizedSablierSender != address(0)) {
301:             authorizedSablierSenders[_authorizedSablierSender] = true;
302:         }
303:     }
```


</details>

## [NonCritical-23] Non constant/immutable state variables are missing a setter post deployment

### Resolution 
Non-constant or non-immutable state variables lacking a setter function can create inflexibility in contract operations. If there's no way to update these variables post-deployment, the contract might not adapt to changing conditions or requirements, which can be a significant drawback, especially in upgradable or long-lived contracts. To resolve this, implement setter functions guarded by appropriate access controls, like `onlyOwner` or similar modifiers, so that these variables can be updated as required while maintaining security. This enables smoother contract maintenance and feature upgrades.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[66](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L66-L66)']
```solidity
66:  uint256 public auctionEndTime;
```


</details>

## [NonCritical-24] Empty revert statement

### Resolution 
Utilizing an empty `revert()` statement in Solidity might cause potential clarity and debugging issues in smart contract development. While `revert()` is designed to halt function execution and revert state changes when conditions aren't met, providing a descriptive error message within it enhances debuggability and transparency. Failing to provide specific reasons for reversion makes it difficult to trace the point of failure in contract interactions, especially for external developers and users interacting with the contract. To enhance clarity, developers should always use `revert("Descriptive error message")` to explain why the execution was halted, ensuring that the cause of reversion is clear, thus aiding in troubleshooting and maintaining transparent contract behavior.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[186](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L186-L186)']
```solidity
186:             revert(); // <= FOUND
```


</details>

## [NonCritical-25] Inconsistent checks of address params against address(0)

### Resolution 
Only some address parameters are checked against address(0), to ensure consistency ensure all address parameters are checked.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L825)']
```solidity
823:     function onStreamCanceled(
824:         uint256 streamId,
825:         address sender, // <= FOUND
826:         uint128 senderAmount,
827:         uint128 
828:     ) external override onlySablier checkEpochRollover {
829:         address streamOwner = _streamIDOwners[streamId];
830: 
831:         if (streamOwner == address(0)) revert StreamOwnerNotFound();
832: 
833:         _redeem(streamOwner);
834: 
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId];
836: 
837:         uint256 amount =
838:             uint256(senderAmount) > nftData.amount ? nftData.amount : uint256(senderAmount);
839: 
840:         _unstakeVested(streamOwner, streamId, amount);
841: 
842:         emit SablierCanceled(streamOwner, streamId, sender, amount);
843:     }
```


</details>

## [NonCritical-26] Simplify complex revert statements

### Resolution 
Simplifying complex revert statements with multiple logical OR (||) operators in Solidity can be achieved by using multiple single revert statements. This involves converting the conditional logic of require into separate if statements, each followed by a revert for specific failing conditions. This approach enhances readability and maintains clarity, especially when dealing with multiple conditions. It allows for more descriptive error messages for each specific case, improving the debugging process and making the code more maintainable. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[288](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L288-L290)']
```solidity
288:         if (
289:             _rewardAdmin == address(0) || _sablier == address(0) || _fjordToken == address(0) // <= FOUND
290:                 || _fjordPoints == address(0) // <= FOUND
291:         ) revert InvalidZeroAddress();
```


</details>

## [NonCritical-27] Constructors should emit an event

### Resolution 
Emitting an event in a constructor of a smart contract provides transparency and traceability in blockchain applications. This event logs the contract’s creation, aiding in monitoring and verifying contract deployment. Although constructors are executed only once, the emitted event ensures the contract's initialization is recorded on the blockchain.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[120](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L120-L120)']
```solidity
120:     constructor( // <= FOUND
121:         address _fjordPoints,
122:         address _auctionToken,
123:         uint256 _biddingTime,
124:         uint256 _totalTokens
125:     ) {
126:         if (_fjordPoints == address(0)) {
127:             revert InvalidFjordPointsAddress();
128:         }
129:         if (_auctionToken == address(0)) {
130:             revert InvalidAuctionTokenAddress();
131:         }
132:         fjordPoints = ERC20Burnable(_fjordPoints);
133:         auctionToken = IERC20(_auctionToken);
134:         owner = msg.sender;
135:         auctionEndTime = block.timestamp.add(_biddingTime);
136:         totalTokens = _totalTokens;
137:     }
```
['[24](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L24-L24)']
```solidity
24:     constructor(address _fjordPoints) { // <= FOUND
25:         if (_fjordPoints == address(0)) revert InvalidAddress();
26: 
27:         fjordPoints = _fjordPoints;
28:         owner = msg.sender;
29:     }
```
['[118](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L118-L118)']
```solidity
118:     constructor() ERC20("BjordBoint", "BJB") { // <= FOUND
119:         owner = msg.sender;
120:         lastDistribution = block.timestamp;
121:         pointsPerEpoch = 100 ether;
122:     }
```
['[281](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L281-L281)']
```solidity
281:     constructor( // <= FOUND
282:         address _fjordToken,
283:         address _rewardAdmin,
284:         address _sablier,
285:         address _authorizedSablierSender,
286:         address _fjordPoints
287:     ) {
288:         if (
289:             _rewardAdmin == address(0) || _sablier == address(0) || _fjordToken == address(0)
290:                 || _fjordPoints == address(0)
291:         ) revert InvalidZeroAddress();
292: 
293:         startTime = block.timestamp;
294:         owner = msg.sender;
295:         fjordToken = ERC20(_fjordToken);
296:         currentEpoch = 1;
297:         rewardAdmin = _rewardAdmin;
298:         sablier = ISablierV2Lockup(_sablier);
299:         points = IFjordPoints(_fjordPoints);
300:         if (_authorizedSablierSender != address(0)) {
301:             authorizedSablierSenders[_authorizedSablierSender] = true;
302:         }
303:     }
```
['[7](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordToken.sol#L7-L7)']
```solidity
7:     constructor() ERC20("Fjord Foundry", "FJO", 18) { // <= FOUND
8:         _mint(msg.sender, 100_000_000 ether);
9:     }
```


</details>

## [NonCritical-28] Function call in event emit

### Resolution 
Emits are designed to make users aware of state variable changes. As such the event declaration should be clear on what it will output, by passing in function calls this can affect the readability of a emit declaration. As such it is advisable to make function calls outside of the event emit and pass the return value into the emit instead.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L570)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount);
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```


</details>

## [NonCritical-29] Errors should have parameters

### Resolution 
In Solidity, custom errors with parameters offer a gas-efficient way to convey detailed information about issues encountered during contract execution. Unlike revert messages, which are strings consuming more gas, custom errors defined with parameters allow developers to specify types and details of errors succinctly. This method enhances debugging, provides clearer insights into contract failures, and improves the developer's and end-user's understanding of what went wrong, all while optimizing for gas usage and maintaining contract efficiency.

Num of instances: 62

### Findings 


<details><summary>Click to show findings</summary>

['[19](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L19-L22)']
```solidity
19:     
22:     error InvalidFjordPointsAddress(); // <= FOUND
```
['[24](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L24-L27)']
```solidity
24:     
27:     error InvalidAuctionTokenAddress(); // <= FOUND
```
['[29](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L29-L32)']
```solidity
29:     
32:     error AuctionAlreadyEnded(); // <= FOUND
```
['[34](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L34-L37)']
```solidity
34:     
37:     error AuctionNotYetEnded(); // <= FOUND
```
['[39](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L39-L42)']
```solidity
39:     
42:     error AuctionEndAlreadyCalled(); // <= FOUND
```
['[44](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L44-L47)']
```solidity
44:     
47:     error NoTokensToClaim(); // <= FOUND
```
['[49](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L49-L52)']
```solidity
49:     
52:     error NoBidsToWithdraw(); // <= FOUND
```
['[54](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L54-L57)']
```solidity
54:     
57:     error InvalidUnbidAmount(); // <= FOUND
```
['[17](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L17-L17)']
```solidity
17:     error NotOwner(); // <= FOUND
```
['[20](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L20-L20)']
```solidity
20:     error InvalidAddress(); // <= FOUND
```
['[20](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L20-L23)']
```solidity
20:     
23:     error InvalidAddress(); // <= FOUND
```
['[25](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L25-L28)']
```solidity
25:     
28:     error DistributionNotAllowedYet(); // <= FOUND
```
['[30](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L30-L33)']
```solidity
30:     
33:     error NotAuthorized(); // <= FOUND
```
['[35](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L35-L38)']
```solidity
35:     
38:     error UnstakingAmountExceedsStakedAmount(); // <= FOUND
```
['[40](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L40-L43)']
```solidity
40:     
43:     error TotalStakedAmountZero(); // <= FOUND
```
['[45](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L45-L48)']
```solidity
45:     
48:     error CallerDisallowed(); // <= FOUND
```
['[45](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L45-L50)']
```solidity
45:     
50:     error CallerDisallowed(); // <= FOUND
```
['[142](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L142-L143)']
```solidity
142:     
143:     error InvalidAmount(); // <= FOUND
```
['[145](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L145-L146)']
```solidity
145:     
146:     error UnstakeEarly(); // <= FOUND
```
['[148](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L148-L149)']
```solidity
148:     
149:     error ClaimTooEarly(); // <= FOUND
```
['[151](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L151-L152)']
```solidity
151:     
152:     error DepositNotFound(); // <= FOUND
```
['[154](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L154-L155)']
```solidity
154:     
155:     error ClaimReceiptNotFound(); // <= FOUND
```
['[157](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L157-L158)']
```solidity
157:     
158:     error NoActiveDeposit(); // <= FOUND
```
['[160](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L160-L161)']
```solidity
160:     
161:     error UnstakeMoreThanDeposit(); // <= FOUND
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L163-L164)']
```solidity
163:     
164:     error NotAStream(); // <= FOUND
```
['[166](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L166-L167)']
```solidity
166:     
167:     error StreamNotSupported(); // <= FOUND
```
['[169](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L169-L170)']
```solidity
169:     
170:     error NotAWarmStream(); // <= FOUND
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L172-L173)']
```solidity
172:     
173:     error InvalidAsset(); // <= FOUND
```
['[175](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L175-L176)']
```solidity
175:     
176:     error NothingToClaim(); // <= FOUND
```
['[178](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L178-L179)']
```solidity
178:     
179:     error StreamOwnerNotFound(); // <= FOUND
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L181-L182)']
```solidity
181:     
182:     error InvalidZeroAddress(); // <= FOUND
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L184-L185)']
```solidity
184:     
185:     error CompleteRequestTooEarly(); // <= FOUND
```
['[19](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L19-L19)']
```solidity
19: error InvalidFjordPointsAddress(); // <= FOUND
```
['[24](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L24-L24)']
```solidity
24: error InvalidAuctionTokenAddress(); // <= FOUND
```
['[29](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L29-L29)']
```solidity
29: error AuctionAlreadyEnded(); // <= FOUND
```
['[34](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L34-L34)']
```solidity
34: error AuctionNotYetEnded(); // <= FOUND
```
['[39](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L39-L39)']
```solidity
39: error AuctionEndAlreadyCalled(); // <= FOUND
```
['[44](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L44-L44)']
```solidity
44: error NoTokensToClaim(); // <= FOUND
```
['[49](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L49-L49)']
```solidity
49: error NoBidsToWithdraw(); // <= FOUND
```
['[54](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L54-L54)']
```solidity
54: error InvalidUnbidAmount(); // <= FOUND
```
['[17](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L17-L17)']
```solidity
17: error NotOwner(); // <= FOUND
```
['[20](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L20-L20)']
```solidity
20: error InvalidAddress(); // <= FOUND
```
['[25](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L25-L25)']
```solidity
25: error DistributionNotAllowedYet(); // <= FOUND
```
['[30](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L30-L30)']
```solidity
30: error NotAuthorized(); // <= FOUND
```
['[35](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L35-L35)']
```solidity
35: error UnstakingAmountExceedsStakedAmount(); // <= FOUND
```
['[40](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L40-L40)']
```solidity
40: error TotalStakedAmountZero(); // <= FOUND
```
['[45](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L45-L45)']
```solidity
45: error CallerDisallowed(); // <= FOUND
```
['[142](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L142-L142)']
```solidity
142: error InvalidAmount(); // <= FOUND
```
['[145](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L145-L145)']
```solidity
145: error UnstakeEarly(); // <= FOUND
```
['[148](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L148-L148)']
```solidity
148: error ClaimTooEarly(); // <= FOUND
```
['[151](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L151-L151)']
```solidity
151: error DepositNotFound(); // <= FOUND
```
['[154](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L154-L154)']
```solidity
154: error ClaimReceiptNotFound(); // <= FOUND
```
['[157](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L157-L157)']
```solidity
157: error NoActiveDeposit(); // <= FOUND
```
['[160](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L160-L160)']
```solidity
160: error UnstakeMoreThanDeposit(); // <= FOUND
```
['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L163-L163)']
```solidity
163: error NotAStream(); // <= FOUND
```
['[166](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L166-L166)']
```solidity
166: error StreamNotSupported(); // <= FOUND
```
['[169](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L169-L169)']
```solidity
169: error NotAWarmStream(); // <= FOUND
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L172-L172)']
```solidity
172: error InvalidAsset(); // <= FOUND
```
['[175](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L175-L175)']
```solidity
175: error NothingToClaim(); // <= FOUND
```
['[178](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L178-L178)']
```solidity
178: error StreamOwnerNotFound(); // <= FOUND
```
['[181](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L181-L181)']
```solidity
181: error InvalidZeroAddress(); // <= FOUND
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L184-L184)']
```solidity
184: error CompleteRequestTooEarly(); // <= FOUND
```


</details>

## [NonCritical-30] Constant state variables defined more than once

### Resolution 
Rather than redefining state variable constant, consider utilising a library to store all constants as this will prevent data redundancy

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[85](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L85-L85)']
```solidity
85: uint256 public constant PRECISION_18 = 1e18; // <= FOUND
```


</details>

## [NonCritical-31] ERC777 tokens can introduce reentrancy risks

### Resolution 
ERC777 is an advanced token standard that introduces hooks, allowing operators to execute additional logic during transfers. While this feature offers greater flexibility, it also opens up the possibility of reentrancy attacks. Specifically, when tokens are sent, the receiving contract's `tokensReceived` hook gets called, and this external call can execute arbitrary code. An attacker can exploit this feature to re-enter the original function, potentially leading to double-spending or other types of financial manipulation.

To mitigate reentrancy risks with ERC777, it's crucial to adopt established security measures, such as utilizing reentrancy guards or following the check-effects-interactions pattern. Some developers opt to stick with the simpler ERC20 standard, which does not have these hooks, to minimize this risk. If you do choose to use ERC777, extreme caution and thorough auditing are advised to secure against potential reentrancy vulnerabilities.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[143](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L143-L151)']
```solidity
143:     function bid(uint256 amount) external { // <= FOUND
144:         if (block.timestamp > auctionEndTime) {
145:             revert AuctionAlreadyEnded();
146:         }
147: 
148:         bids[msg.sender] = bids[msg.sender].add(amount);
149:         totalBids = totalBids.add(amount);
150: 
151:         fjordPoints.transferFrom(msg.sender, address(this), amount); // <= FOUND
152:         emit BidAdded(msg.sender, amount);
153:     }
```
['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L63)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens); // <= FOUND
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```
['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L387)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards { // <= FOUND
369:         
370:         if (_amount == 0) revert InvalidAmount();
371: 
372:         
373:         userData[msg.sender].unredeemedEpoch = currentEpoch;
374: 
375:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
376:         if (dr.epoch == 0) {
377:             dr.staked = _amount;
378:             dr.epoch = currentEpoch;
379:             _activeDeposits[msg.sender].add(currentEpoch);
380:         } else {
381:             dr.staked += _amount;
382:         }
383: 
384:         newStaked += _amount;
385: 
386:         
387:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount); // <= FOUND
388:         points.onStaked(msg.sender, _amount);
389: 
390:         emit Staked(msg.sender, currentEpoch, _amount);
391:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L763)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin { // <= FOUND
756:         
757:         if (_amount == 0) revert InvalidAmount();
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount); // <= FOUND
764: 
765:         _checkEpochRollover();
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```


</details>

## [NonCritical-32] Custom implementation of a `roundUp` operation, consider using `mulDivUp` instead

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[332](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L332-L332)']
```solidity
332:         return uint16((_timestamp - startTime) / epochDuration) + 1; // <= FOUND
```


</details>

## [Gas-1] The usage of SafeMath is useless in solidity versions 0.8.0 and above hence wasting gas 

### Resolution 
Remove the library and refactor where it's used to regular arithmetic

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[13](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L13-L14)']
```solidity
13: contract FjordAuction {
14:     using SafeMath for uint256; // <= FOUND
15: 
57:     ERC20Burnable public fjordPoints;
58: 
60:     IERC20 public auctionToken;
61: 
63:     address public owner;
64: 
66:     uint256 public auctionEndTime;
67: 
69:     uint256 public totalBids;
70: 
72:     uint256 public totalTokens;
73: 
75:     uint256 public multiplier;
76: 
78:     bool public ended;
79: 
81:     mapping(address => uint256) public bids;
82: 
84:     uint256 public constant PRECISION_18 = 1e18;
85: 
143: }
```
['[14](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L14-L15)']
```solidity
14: contract FjordPoints is ERC20, ERC20Burnable, IFjordPoints {
15:     using SafeMath for uint256; // <= FOUND
16: 
48:     address public owner;
49: 
51:     address public staking;
52: 
54:     uint256 public constant EPOCH_DURATION = 1 weeks;
55: 
57:     uint256 public lastDistribution;
58: 
60:     uint256 public totalStaked;
61: 
63:     uint256 public pointsPerToken;
64: 
66:     uint256 public totalPoints;
67: 
69:     uint256 public pointsPerEpoch;
70: 
75:     mapping(address => UserInfo) public users;
76: 
78:     uint256 public constant PRECISION_18 = 1e18;
79: 
171: }
```


</details>

## [Gas-2] State variables used within a function more than once should be cached to save gas 

### Resolution 
Cache such variables and perform operations on them, if operations include modifications to the state variable(s) then remember to equate the state variable to it's cached counterpart at the end

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[691](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L691-L722)']
```solidity
691:     function _checkEpochRollover() internal { // <= FOUND 'function _checkEpochRollover'
692:         uint16 latestEpoch = getEpoch(block.timestamp);
693: 
694:         if (latestEpoch > currentEpoch) {
695:             
696:             currentEpoch = latestEpoch;
697: 
698:             if (totalStaked > 0) {
699:                 uint256 currentBalance = fjordToken.balanceOf(address(this));
700: 
701:                 
702:                 uint256 pendingRewards = (currentBalance + totalVestedStaked + newVestedStaked) // <= FOUND 'newVestedStaked'
703:                     - totalStaked - newStaked - totalRewards; // <= FOUND 'newStaked'
704:                 uint256 pendingRewardsPerToken = (pendingRewards * PRECISION_18) / totalStaked;
705:                 totalRewards += pendingRewards; // <= FOUND 'totalRewards'
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) { // <= FOUND 'lastEpochRewarded'
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken; // <= FOUND 'lastEpochRewarded'
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
709:                 }
710:             } else {
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) { // <= FOUND 'lastEpochRewarded'
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded]; // <= FOUND 'lastEpochRewarded'
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
714:                 }
715:             }
716: 
717:             totalStaked += newStaked; // <= FOUND 'newStaked'
718:             totalVestedStaked += newVestedStaked; // <= FOUND 'newVestedStaked'
719:             newStaked = 0; // <= FOUND 'newStaked'
720:             newVestedStaked = 0; // <= FOUND 'newVestedStaked'
721: 
722:             lastEpochRewarded = currentEpoch - 1; // <= FOUND 'lastEpochRewarded'
723:         }
724:     }
```


</details>

## [Gas-3] x + y is more efficient than using += for state variables (likewise for -=)

### Resolution 
In instances found where either += or -= are used against state variables use x = x + y instead

Num of instances: 9

### Findings 


<details><summary>Click to show findings</summary>

['[691](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L691-L705)']
```solidity
691:     function _checkEpochRollover() internal {
692:         uint16 latestEpoch = getEpoch(block.timestamp);
693: 
694:         if (latestEpoch > currentEpoch) {
695:             
696:             currentEpoch = latestEpoch;
697: 
698:             if (totalStaked > 0) {
699:                 uint256 currentBalance = fjordToken.balanceOf(address(this));
700: 
701:                 
702:                 uint256 pendingRewards = (currentBalance + totalVestedStaked + newVestedStaked)
703:                     - totalStaked - newStaked - totalRewards;
704:                 uint256 pendingRewardsPerToken = (pendingRewards * PRECISION_18) / totalStaked;
705:                 totalRewards += pendingRewards; // <= FOUND
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
709:                 }
710:             } else {
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
714:                 }
715:             }
716: 
717:             totalStaked += newStaked; // <= FOUND
718:             totalVestedStaked += newVestedStaked; // <= FOUND
719:             newStaked = 0;
720:             newVestedStaked = 0;
721: 
722:             lastEpochRewarded = currentEpoch - 1;
723:         }
724:     }
```
['[729](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L729-L747)']
```solidity
729:     function _redeem(address sender) internal {
730:         
731:         UserData storage ud = userData[sender];
732: 
733:         ud.unclaimedRewards +=
734:             calculateReward(ud.totalStaked, ud.lastClaimedEpoch, currentEpoch - 1);
735:         ud.lastClaimedEpoch = currentEpoch - 1;
736: 
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch) {
738:             
739:             DepositReceipt memory deposit = deposits[sender][ud.unredeemedEpoch];
740: 
741:             
742:             ud.unclaimedRewards += calculateReward(
743:                 deposit.staked + deposit.vestedStaked, ud.unredeemedEpoch, currentEpoch - 1
744:             );
745: 
746:             ud.unredeemedEpoch = 0;
747:             ud.totalStaked += (deposit.staked + deposit.vestedStaked); // <= FOUND
748:         }
749:     }
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L475)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount)
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount; // <= FOUND
472:             userData[msg.sender].totalStaked -= _amount; // <= FOUND
473:         } else {
474:             
475:             newStaked -= _amount; // <= FOUND
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total);
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```
['[521](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L521-L537)']
```solidity
521:     function _unstakeVested(address streamOwner, uint256 _streamID, uint256 amount) internal {
522:         NFTData storage data = _streamIDs[streamOwner][_streamID];
523:         DepositReceipt storage dr = deposits[streamOwner][data.epoch];
524:         if (amount > data.amount) revert InvalidAmount();
525: 
526:         bool isFullUnstaked = data.amount == amount;
527:         uint16 epoch = data.epoch;
528: 
529:         dr.vestedStaked -= amount;
530:         if (currentEpoch != data.epoch) {
531:             totalStaked -= amount; // <= FOUND
532:             totalVestedStaked -= amount; // <= FOUND
533:             userData[streamOwner].totalStaked -= amount; // <= FOUND
534:         } else {
535:             
536:             newStaked -= amount; // <= FOUND
537:             newVestedStaked -= amount; // <= FOUND
538:         }
539: 
540:         if (dr.vestedStaked == 0 && dr.staked == 0) {
541:             
542:             if (userData[streamOwner].unredeemedEpoch == currentEpoch) {
543:                 userData[streamOwner].unredeemedEpoch = 0;
544:             }
545:             delete deposits[streamOwner][data.epoch];
546:             _activeDeposits[streamOwner].remove(data.epoch);
547:         }
548:         
549:         if (isFullUnstaked) {
550:             delete _streamIDs[streamOwner][_streamID];
551:             delete _streamIDOwners[_streamID];
552:         } else {
553:             data.amount -= amount;
554:         }
555: 
556:         
557:         if (isFullUnstaked) {
558:             sablier.transferFrom({ from: address(this), to: streamOwner, tokenId: _streamID });
559:         }
560: 
561:         points.onUnstaked(msg.sender, amount);
562: 
563:         emit VestedUnstaked(streamOwner, epoch, amount, _streamID);
564:     }
```
['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L598)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount; // <= FOUND
598:         userData[msg.sender].totalStaked -= totalStakedAmount; // <= FOUND
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount);
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```
['[368](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L368-L384)']
```solidity
368:     function stake(uint256 _amount) external checkEpochRollover redeemPendingRewards {
369:         
370:         if (_amount == 0) revert InvalidAmount();
371: 
372:         
373:         userData[msg.sender].unredeemedEpoch = currentEpoch;
374: 
375:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
376:         if (dr.epoch == 0) {
377:             dr.staked = _amount;
378:             dr.epoch = currentEpoch;
379:             _activeDeposits[msg.sender].add(currentEpoch);
380:         } else {
381:             dr.staked += _amount;
382:         }
383: 
384:         newStaked += _amount; // <= FOUND
385: 
386:         
387:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
388:         points.onStaked(msg.sender, _amount);
389: 
390:         emit Staked(msg.sender, currentEpoch, _amount);
391:     }
```
['[397](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L397-L432)']
```solidity
397:     function stakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards {
398:         
399:         if (!sablier.isStream(_streamID)) revert NotAStream();
400:         if (sablier.isCold(_streamID)) revert NotAWarmStream();
401: 
402:         
403:         if (!authorizedSablierSenders[sablier.getSender(_streamID)]) {
404:             revert StreamNotSupported();
405:         }
406:         if (address(sablier.getAsset(_streamID)) != address(fjordToken)) revert InvalidAsset();
407: 
408:         uint128 depositedAmount = sablier.getDepositedAmount(_streamID);
409:         uint128 withdrawnAmount = sablier.getWithdrawnAmount(_streamID);
410:         uint128 refundedAmount = sablier.getRefundedAmount(_streamID);
411: 
412:         if (depositedAmount - (withdrawnAmount + refundedAmount) <= 0) revert InvalidAmount();
413: 
414:         uint256 _amount = depositedAmount - (withdrawnAmount + refundedAmount);
415: 
416:         
417:         userData[msg.sender].unredeemedEpoch = currentEpoch;
418: 
419:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
420:         if (dr.epoch == 0) {
421:             dr.vestedStaked = _amount;
422:             dr.epoch = currentEpoch;
423: 
424:             _activeDeposits[msg.sender].add(currentEpoch);
425:         } else {
426:             dr.vestedStaked += _amount;
427:         }
428: 
429:         _streamIDs[msg.sender][_streamID] = NFTData({ epoch: currentEpoch, amount: _amount });
430:         _streamIDOwners[_streamID] = msg.sender;
431:         newStaked += _amount; // <= FOUND
432:         newVestedStaked += _amount; // <= FOUND
433: 
434:         
435:         sablier.transferFrom({ from: msg.sender, to: address(this), tokenId: _streamID });
436:         points.onStaked(msg.sender, _amount);
437: 
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount);
439:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L650)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount); // <= FOUND
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount);
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```
['[662](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L662-L680)']
```solidity
662:     function completeClaimRequest()
663:         external
664:         checkEpochRollover
665:         redeemPendingRewards
666:         returns (uint256 rewardAmount)
667:     {
668:         ClaimReceipt memory cr = claimReceipts[msg.sender];
669: 
670:         
671:         if (cr.requestEpoch < 1) revert ClaimReceiptNotFound();
672:         
673:         if (currentEpoch - cr.requestEpoch <= claimCycle) revert CompleteRequestTooEarly();
674: 
675:         
676:         rewardAmount = cr.amount;
677: 
678:         userData[msg.sender].unclaimedRewards -= rewardAmount;
679: 
680:         totalRewards -= rewardAmount; // <= FOUND
681:         delete claimReceipts[msg.sender];
682: 
683:         
684:         fjordToken.safeTransfer(msg.sender, rewardAmount);
685: 
686:         emit RewardClaimed(msg.sender, rewardAmount);
687:     }
```


</details>

## [Gas-4] Public functions not used internally can be marked as external to save gas

### Resolution 
Public functions that aren't used internally in Solidity contracts should be made external to optimize gas usage and improve contract efficiency. External functions can only be called from outside the contract, and their arguments are directly read from the calldata, which is more gas-efficient than loading them into memory, as is the case for public functions. By using external visibility, developers can reduce gas consumption for external calls and ensure that the contract operates more cost-effectively for users. Moreover, setting the appropriate visibility level for functions also enhances code readability and maintainability, promoting a more secure and well-structured contract design.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[339](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L339-L339)']
```solidity
339:     function getStreamData(address _user, uint256 _streamID) public view returns (NFTData memory) 
```
['[343](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L343-L343)']
```solidity
343:     function getStreamOwner(uint256 _streamID) public view returns (address) 
```


</details>

## [Gas-5] Usage of smaller uint/int types causes overhead

### Resolution 
When using a smaller int/uint type it first needs to be converted to it's 258 bit counterpart to be operated, this increases the gass cost and thus should be avoided. However it does make sense to use smaller int/uint values within structs provided you pack the struct properly.

Num of instances: 34

### Findings 


<details><summary>Click to show findings</summary>

['[253](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L253-L254)']
```solidity
253:     
254:     uint8 public constant lockCycle = 6; // <= FOUND
```
['[259](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L259-L260)']
```solidity
259:     
260:     uint8 public constant claimCycle = 3; // <= FOUND
```
['[253](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L253-L253)']
```solidity
253: uint8 public constant lockCycle = 6; // <= FOUND
```
['[259](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L259-L259)']
```solidity
259: uint8 public constant claimCycle = 3; // <= FOUND
```
['[13](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L13-L13)']
```solidity
13:     uint16 epoch; // <= FOUND
```
['[19](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L19-L19)']
```solidity
19:     uint16 requestEpoch; // <= FOUND
```
['[31](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L31-L31)']
```solidity
31:     uint16 unredeemedEpoch; // <= FOUND
```
['[32](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L32-L32)']
```solidity
32:     uint16 lastClaimedEpoch; // <= FOUND
```
['[51](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L51-L59)']
```solidity
51:     
59:     event Staked(address indexed user, uint16 indexed epoch, uint256 amount); // <= FOUND
```
['[58](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L58-L64)']
```solidity
58:     
63:     event VestedStaked(
64:         address indexed user, uint16 indexed epoch, uint256 indexed streamID, uint256 amount // <= FOUND
65:     );
```
['[65](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L65-L68)']
```solidity
65:     
68:     event RewardAdded(uint16 indexed epoch, address rewardAdmin, uint256 amount); // <= FOUND
```
['[88](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L88-L92)']
```solidity
88:     
92:     event Unstaked(address indexed user, uint16 indexed epoch, uint256 stakedAmount); // <= FOUND
```
['[95](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L95-L101)']
```solidity
95:     
100:     event VestedUnstaked(
101:         address indexed user, uint16 indexed epoch, uint256 stakedAmount, uint256 streamID // <= FOUND
102:     );
```
['[114](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L114-L117)']
```solidity
114:     
117:     event ClaimReceiptCreated(address indexed user, uint16 requestEpoch); // <= FOUND
```
['[119](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L119-L122)']
```solidity
119:     
122:     event RewardPerTokenChanged(uint16 epoch, uint256 rewardPerToken); // <= FOUND
```
['[200](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L200-L201)']
```solidity
200:     
201:     mapping(address user => mapping(uint16 epoch => DepositReceipt)) public deposits; // <= FOUND
```
['[219](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L219-L221)']
```solidity
219:     
221:     mapping(uint16 epoch => uint256) public rewardPerToken; // <= FOUND
```
['[237](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L237-L238)']
```solidity
237:     
238:     uint16 public currentEpoch; // <= FOUND
```
['[240](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L240-L241)']
```solidity
240:     
241:     uint16 public lastEpochRewarded; // <= FOUND
```
['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L457)']
```solidity
449:     
457:     function unstake(uint16 _epoch, uint256 _amount) // <= FOUND
458:         external
459:         checkEpochRollover
460:         redeemPendingRewards
461:         returns (uint256 total)
462:     {
```
['[527](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L527-L527)']
```solidity
527:         uint16 epoch = data.epoch; // <= FOUND
```
['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579:         for (uint16 i = 0; i < activeDeposits.length; i++) { // <= FOUND
```
['[580](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L580-L580)']
```solidity
580:             uint16 epoch = uint16(activeDeposits[i]); // <= FOUND
```
['[692](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L692-L692)']
```solidity
692:         uint16 latestEpoch = getEpoch(block.timestamp); // <= FOUND
```
['[706](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L706-L706)']
```solidity
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) { // <= FOUND
```
['[760](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L760-L761)']
```solidity
760:         
761:         uint16 previousEpoch = currentEpoch; // <= FOUND
```
['[775](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L775-L780)']
```solidity
775:     
780:     function calculateReward(uint256 _amount, uint16 _fromEpoch, uint16 _toEpoch) // <= FOUND
781:         internal
782:         view
783:         returns (uint256 rewardAmount)
784:     {
```
['[237](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L237-L237)']
```solidity
237: uint16 public currentEpoch; // <= FOUND
```
['[240](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L240-L240)']
```solidity
240: uint16 public lastEpochRewarded; // <= FOUND
```
['[408](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L408-L408)']
```solidity
408:         uint128 depositedAmount = sablier.getDepositedAmount(_streamID); // <= FOUND
```
['[409](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L409-L409)']
```solidity
409:         uint128 withdrawnAmount = sablier.getWithdrawnAmount(_streamID); // <= FOUND
```
['[410](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L410-L410)']
```solidity
410:         uint128 refundedAmount = sablier.getRefundedAmount(_streamID); // <= FOUND
```
['[792](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L792-L804)']
```solidity
792:     
800:     function onStreamWithdrawn(
801:         uint256, 
802:         address, 
803:         address, 
804:         uint128  // <= FOUND
805:     ) external override onlySablier {
```
['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L837)']
```solidity
823:     
833:     function onStreamCanceled(
834:         uint256 streamId,
835:         address sender,
836:         uint128 senderAmount, // <= FOUND
837:         uint128  // <= FOUND
838:     ) external override onlySablier checkEpochRollover {
```


</details>

## [Gas-6] Use != 0 instead of > 0

### Resolution 
Replace spotted instances with != 0 for uints as this uses less gas

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[256](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L256-L256)']
```solidity
256:         if (pointsToClaim > 0) { // <= FOUND
```
['[627](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L627-L630)']
```solidity
627:         
628:         
629:         if (
630:             claimReceipts[msg.sender].requestEpoch > 0 // <= FOUND
631:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
632:         ) revert ClaimTooEarly();
```
['[698](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L698-L698)']
```solidity
698:             if (totalStaked > 0) { // <= FOUND
```
['[737](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L737-L737)']
```solidity
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch) { // <= FOUND
```


</details>

## [Gas-7] Default bool values are manually reset

### Resolution 
Using .delete is better than resetting a Solidity variable to its default value manually because it frees up storage space on the Ethereum blockchain, resulting in gas cost savings. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L362)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner { // <= FOUND
362:         if (authorizedSablierSenders[_address]) authorizedSablierSenders[_address] = false; // <= FOUND
363:     }
```


</details>

## [Gas-8] Default int values are manually reset

### Resolution 
Using .delete is better than resetting a Solidity variable to its default value manually because it frees up storage space on the Ethereum blockchain, resulting in gas cost savings.

Num of instances: 7

### Findings 


<details><summary>Click to show findings</summary>

['[218](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L218-L218)']
```solidity
218:         bids[msg.sender] = 0; // <= FOUND
```
['[481](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L481-L481)']
```solidity
481:                 userData[msg.sender].unredeemedEpoch = 0; // <= FOUND
```
['[543](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L543-L543)']
```solidity
543:                 userData[streamOwner].unredeemedEpoch = 0; // <= FOUND
```
['[593](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L593-L594)']
```solidity
593:                 
594:                 dr.staked = 0; // <= FOUND
```
['[719](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L719-L719)']
```solidity
719:             newStaked = 0; // <= FOUND
```
['[720](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L720-L720)']
```solidity
720:             newVestedStaked = 0; // <= FOUND
```
['[746](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L746-L746)']
```solidity
746:             ud.unredeemedEpoch = 0; // <= FOUND
```


</details>

## [Gas-9] For loops in public or external functions should be avoided due to high gas costs and possible DOS

### Resolution 
In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[570](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L570-L579)']
```solidity
570:     function unstakeAll()
571:         external
572:         checkEpochRollover
573:         redeemPendingRewards
574:         returns (uint256 totalStakedAmount)
575:     {
576:         uint256[] memory activeDeposits = getActiveDeposits(msg.sender);
577:         if (activeDeposits.length == 0) revert NoActiveDeposit();
578: 
579:         for (uint16 i = 0; i < activeDeposits.length; i++) { // <= FOUND
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
596: 
597:         totalStaked -= totalStakedAmount;
598:         userData[msg.sender].totalStaked -= totalStakedAmount;
599: 
600:         fjordToken.transfer(msg.sender, totalStakedAmount);
601:         points.onUnstaked(msg.sender, totalStakedAmount);
602: 
603:         
604:         emit UnstakedAll(
605:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
606:         );
607:     }
```


</details>

## [Gas-10] Mappings used within a function more than once should be cached to save gas

### Resolution 
Cache such mappings and perform operations on them, if operations include modifications to the mapping(s) then remember to equate the mapping to it's cached counterpart at the end

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[449](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L449-L481)']
```solidity
449:     function unstake(uint16 _epoch, uint256 _amount) // <= FOUND
450:         external
451:         checkEpochRollover
452:         redeemPendingRewards
453:         returns (uint256 total)
454:     {
455:         if (_amount == 0) revert InvalidAmount();
456: 
457:         DepositReceipt storage dr = deposits[msg.sender][_epoch];
458: 
459:         if (dr.epoch == 0) revert DepositNotFound();
460:         if (dr.staked < _amount) revert UnstakeMoreThanDeposit();
461: 
462:         
463:         if (currentEpoch != _epoch) {
464:             
465:             if (currentEpoch - _epoch <= lockCycle) revert UnstakeEarly();
466:         }
467: 
468:         
469:         dr.staked -= _amount;
470:         if (currentEpoch != _epoch) {
471:             totalStaked -= _amount;
472:             userData[msg.sender].totalStaked -= _amount; // <= FOUND
473:         } else {
474:             
475:             newStaked -= _amount;
476:         }
477: 
478:         if (dr.staked == 0 && dr.vestedStaked == 0) {
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) { // <= FOUND
481:                 userData[msg.sender].unredeemedEpoch = 0; // <= FOUND
482:             }
483:             delete deposits[msg.sender][_epoch];
484:             _activeDeposits[msg.sender].remove(_epoch);
485:         }
486: 
487:         total = _amount;
488: 
489:         
490:         fjordToken.safeTransfer(msg.sender, total);
491:         points.onUnstaked(msg.sender, _amount);
492: 
493:         emit Unstaked(msg.sender, _epoch, _amount);
494:     }
```


</details>

## [Gas-11] Use assembly to check for the zero address

### Resolution 
Using assembly for address comparisons in Solidity can save gas because it allows for more direct access to the Ethereum Virtual Machine (EVM), reducing the overhead of higher-level operations. Solidity's high-level abstraction simplifies coding but can introduce additional gas costs. Using assembly for simple operations like address comparisons can be more gas-efficient.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L164)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner {
164:         if (_newOwner == address(0)) revert InvalidAddress(); // <= FOUND
165:         owner = _newOwner;
166:     }
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L173)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner {
173:         if (_staking == address(0)) { // <= FOUND
174:             revert InvalidAddress();
175:         }
176: 
177:         staking = _staking;
178:     }
```
['[347](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L347-L348)']
```solidity
347:     function setOwner(address _newOwner) external onlyOwner {
348:         if (_newOwner == address(0)) revert InvalidZeroAddress(); // <= FOUND
349:         owner = _newOwner;
350:     }
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L353)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner {
353:         if (_rewardAdmin == address(0)) revert InvalidZeroAddress(); // <= FOUND
354:         rewardAdmin = _rewardAdmin;
355:     }
```
['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L831)']
```solidity
823:     function onStreamCanceled(
824:         uint256 streamId,
825:         address sender,
826:         uint128 senderAmount,
827:         uint128 
828:     ) external override onlySablier checkEpochRollover {
829:         address streamOwner = _streamIDOwners[streamId];
830: 
831:         if (streamOwner == address(0)) revert StreamOwnerNotFound(); // <= FOUND
832: 
833:         _redeem(streamOwner);
834: 
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId];
836: 
837:         uint256 amount =
838:             uint256(senderAmount) > nftData.amount ? nftData.amount : uint256(senderAmount);
839: 
840:         _unstakeVested(streamOwner, streamId, amount);
841: 
842:         emit SablierCanceled(streamOwner, streamId, sender, amount);
843:     }
```


</details>

## [Gas-12] Divisions which do not divide by -X cannot overflow or underflow so such operations can be unchecked to save gas

### Resolution 
Make such found divisions are unchecked when ensured it is safe to do so

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L645)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] =
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2; // <= FOUND
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount);
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```


</details>

## [Gas-13] State variables which are not modified within functions should be set as constants or immutable for values set at deployment

### Resolution 
Set state variables listed below as constant or immutable for values set at deployment. Ensure it is safe to do so

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[66](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L66-L66)']
```solidity
66:  uint256 public auctionEndTime; // <= FOUND
```


</details>

## [Gas-14] Divisions of powers of 2 can be replaced by a right shift operation to save gas

### Resolution 
Replace such found divisions with right shift operations when ensured it is safe to do so. NOTE: This only applies to uint variables!

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[645](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L645-L645)']
```solidity
645:         penaltyAmount = rewardAmount / 2; // <= FOUND
```


</details>

## [Gas-15] Structs can be packed into fewer storage slots

### Resolution 
In Solidity, each storage slot has a size of 32 bytes. If a struct contains multiple uint values, it's efficient to pack these into as few storage slots as possible to optimize gas usage. The EVM (Ethereum Virtual Machine) charges gas for each storage operation, so minimizing the number of slots used can result in substantial gas savings. This can be achieved by ordering struct fields according to their size or by using smaller data types where possible. However, developers must balance these optimizations with the need for code clarity and the precision requirements of their application. Always ensure that data packing does not compromise the functionality or security of the contract.

Num of instances: 3

### Findings 


<details><summary>Click to show findings</summary>

['[12](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L12-L15)']
```solidity
12: struct DepositReceipt {
13:     uint16 epoch;
14:     uint256 staked; // <= FOUND
15:     uint256 vestedStaked; // <= FOUND
16: }
```
['[28](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L28-L30)']
```solidity
28: struct UserData {
29:     uint256 totalStaked; // <= FOUND
30:     uint256 unclaimedRewards; // <= FOUND
31:     uint16 unredeemedEpoch;
32:     uint16 lastClaimedEpoch;
33: }
```
['[72](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L72-L78)']
```solidity
72:     struct UserInfo {
73:         
74:         uint256 stakedAmount; // <= FOUND
75:         
76:         uint256 pendingPoints; // <= FOUND
77:         
78:         uint256 lastPointsPerToken; // <= FOUND
79:     }
```


</details>

## [Gas-16] Consider using OZ EnumerateSet in place of nested mappings

### Resolution 
Nested mappings and multi-dimensional arrays in Solidity operate through a process of double hashing, wherein the original storage slot and the first key are concatenated and hashed, and then this hash is again concatenated with the second key and hashed. This process can be quite gas expensive due to the double-hashing operation and subsequent storage operation (sstore).

A possible optimization involves manually concatenating the keys followed by a single hash operation and an sstore. However, this technique introduces the risk of storage collision, especially when there are other nested hash maps in the contract that use the same key types. Because Solidity is unaware of the number and structure of nested hash maps in a contract, it follows a conservative approach in computing the storage slot to avoid possible collisions.

OpenZeppelin's EnumerableSet provides a potential solution to this problem. It creates a data structure that combines the benefits of set operations with the ability to enumerate stored elements, which is not natively available in Solidity. EnumerableSet handles the element uniqueness internally and can therefore provide a more gas-efficient and collision-resistant alternative to nested mappings or multi-dimensional arrays in certain scenarios. 

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[200](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L200-L200)']
```solidity
200:  mapping(address user => mapping(uint16 epoch => DepositReceipt)) public deposits; // <= FOUND
```
['[209](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L209-L209)']
```solidity
209:  mapping(address user => mapping(uint256 streamID => NFTData)) private _streamIDs; // <= FOUND
```


</details>

## [Gas-17] Use assembly to emit events

### Resolution 
With the use of inline assembly in Solidity, we can take advantage of low-level features like scratch space and the free memory pointer, offering more gas-efficient ways of emitting events. The scratch space is a certain area of memory where we can temporarily store data, and the free memory pointer indicates the next available memory slot. Using these, we can efficiently assemble event data without incurring additional memory expansion costs. However, safety is paramount: to avoid overwriting or leakage, we must cache the free memory pointer before use and restore it afterward, ensuring that it points to the correct memory location post-operation.

Num of instances: 20

### Findings 


<details><summary>Click to show findings</summary>

['[152](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L152-L152)']
```solidity
152:         emit BidAdded(msg.sender, amount); // <= FOUND
```
['[175](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L175-L175)']
```solidity
175:         emit BidWithdrawn(msg.sender, amount); // <= FOUND
```
['[190](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L190-L190)']
```solidity
190:         emit AuctionEnded(totalBids, totalTokens); // <= FOUND
```
['[221](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L221-L221)']
```solidity
221:         emit TokensClaimed(msg.sender, claimable); // <= FOUND
```
['[65](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L65-L65)']
```solidity
65:         emit AuctionCreated(auctionAddress); // <= FOUND
```
['[206](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L206-L206)']
```solidity
206:         emit Staked(user, amount); // <= FOUND
```
['[226](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L226-L226)']
```solidity
226:         emit Unstaked(user, amount); // <= FOUND
```
['[247](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L247-L247)']
```solidity
247:         emit PointsDistributed(pointsPerEpoch, pointsPerToken); // <= FOUND
```
['[259](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L259-L259)']
```solidity
259:             emit PointsClaimed(msg.sender, pointsToClaim); // <= FOUND
```
['[390](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L390-L390)']
```solidity
390:         emit Staked(msg.sender, currentEpoch, _amount); // <= FOUND
```
['[438](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L438-L438)']
```solidity
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount); // <= FOUND
```
['[493](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L493-L493)']
```solidity
493:         emit Unstaked(msg.sender, _epoch, _amount); // <= FOUND
```
['[563](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L563-L563)']
```solidity
563:         emit VestedUnstaked(streamOwner, epoch, amount, _streamID); // <= FOUND
```
['[604](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L604-L605)']
```solidity
604:         
605:         emit UnstakedAll( // <= FOUND
606:             msg.sender, totalStakedAmount, activeDeposits, getActiveDeposits(msg.sender)
607:         );
```
['[639](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L639-L639)']
```solidity
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch); // <= FOUND
```
['[656](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L656-L656)']
```solidity
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount); // <= FOUND
```
['[686](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L686-L686)']
```solidity
686:         emit RewardClaimed(msg.sender, rewardAmount); // <= FOUND
```
['[708](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L708-L708)']
```solidity
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
```
['[767](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L767-L767)']
```solidity
767:         emit RewardAdded(previousEpoch, msg.sender, _amount); // <= FOUND
```
['[842](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L842-L842)']
```solidity
842:         emit SablierCanceled(streamOwner, streamId, sender, amount); // <= FOUND
```


</details>

## [Gas-18] Use solady library where possible to save gas

### Resolution 
The following OpenZeppelin imports have a Solady equivalent, as such they can be used to save GAS as Solady modules have been specifically designed to be as GAS efficient as possible

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[5](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L5-L5)']
```solidity
5: import { IERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol"; // <= FOUND
```
['[4](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L4-L4)']
```solidity
4: import { ERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol"; // <= FOUND
```


</details>

## [Gas-19] Using private rather than public for constants and immutables, saves gas

### Resolution 
Using private visibility for constants and immutables in Solidity instead of public can save gas. This is because private elements are not included in the contract's ABI, reducing the deployment and interaction costs. To achieve better efficiency, it is recommended to use private visibility when external access is not needed.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[85](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L85-L85)']
```solidity
85: uint256 public constant PRECISION_18 = 1e18; // <= FOUND
```
['[54](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L54-L54)']
```solidity
54: uint256 public constant EPOCH_DURATION = 1 weeks; // <= FOUND
```
['[250](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L250-L250)']
```solidity
250: uint256 public constant epochDuration = 86_400 * 7;  // <= FOUND
```
['[253](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L253-L253)']
```solidity
253: uint8 public constant lockCycle = 6; // <= FOUND
```
['[259](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L259-L259)']
```solidity
259: uint8 public constant claimCycle = 3; // <= FOUND
```


</details>

## [Gas-20] Mark Functions That Revert For Normal Users As payable

### Resolution 
In Solidity, marking functions as `payable` allows them to accept Ether. If a function is known to revert for regular users (non-admin or specific roles) but needs to be accessible to others, marking it as `payable` can be beneficial. This ensures that even if a regular user accidentally sends Ether to the function, the Ether won't be trapped, as the function reverts, returning the funds. This can save gas by avoiding unnecessary failure handling in the function itself. Resolution: Carefully assess the roles and access patterns, and mark functions that should revert for regular users as `payable` to handle accidental Ether transfers.

Num of instances: 9

### Findings 


<details><summary>Click to show findings</summary>

['[163](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L163-L163)']
```solidity
163:     function setOwner(address _newOwner) external onlyOwner {
164:         if (_newOwner == address(0)) revert InvalidAddress();
165:         owner = _newOwner;
166:     }
```
['[52](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L52-L52)']
```solidity
52:     function createAuction(
53:         address auctionToken,
54:         uint256 biddingTime,
55:         uint256 totalTokens,
56:         bytes32 salt
57:     ) external onlyOwner {
58:         address auctionAddress = address(
59:             new FjordAuction{ salt: salt }(fjordPoints, auctionToken, biddingTime, totalTokens)
60:         );
61: 
62:         
63:         IERC20(auctionToken).transferFrom(msg.sender, auctionAddress, totalTokens);
64: 
65:         emit AuctionCreated(auctionAddress);
66:     }
```
['[172](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L172-L172)']
```solidity
172:     function setStakingContract(address _staking) external onlyOwner {
173:         if (_staking == address(0)) {
174:             revert InvalidAddress();
175:         }
176: 
177:         staking = _staking;
178:     }
```
['[184](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L184-L184)']
```solidity
184:     function setPointsPerEpoch(uint256 _points) external onlyOwner checkDistribution {
185:         if (_points == 0) {
186:             revert();
187:         }
188: 
189:         pointsPerEpoch = _points;
190:     }
```
['[347](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L347-L347)']
```solidity
347:     function setOwner(address _newOwner) external onlyOwner {
348:         if (_newOwner == address(0)) revert InvalidZeroAddress();
349:         owner = _newOwner;
350:     }
```
['[352](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L352-L352)']
```solidity
352:     function setRewardAdmin(address _rewardAdmin) external onlyOwner {
353:         if (_rewardAdmin == address(0)) revert InvalidZeroAddress();
354:         rewardAdmin = _rewardAdmin;
355:     }
```
['[357](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L357-L357)']
```solidity
357:     function addAuthorizedSablierSender(address _address) external onlyOwner {
358:         authorizedSablierSenders[_address] = true;
359:     }
```
['[361](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L361-L361)']
```solidity
361:     function removeAuthorizedSablierSender(address _address) external onlyOwner {
362:         if (authorizedSablierSenders[_address]) authorizedSablierSenders[_address] = false;
363:     }
```
['[755](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L755-L755)']
```solidity
755:     function addReward(uint256 _amount) external onlyRewardAdmin {
756:         
757:         if (_amount == 0) revert InvalidAmount();
758: 
759:         
760:         uint16 previousEpoch = currentEpoch;
761: 
762:         
763:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount);
764: 
765:         _checkEpochRollover();
766: 
767:         emit RewardAdded(previousEpoch, msg.sender, _amount);
768:     }
```


</details>

## [Gas-21] Lack of unchecked in loops

### Resolution 
In Solidity, the `unchecked` block allows arithmetic operations to not revert on overflow. Without using `unchecked` in loops, extra gas is consumed due to overflow checks. If it's certain that overflows won't occur within the loop, using `unchecked` can make the loop more gas-efficient by skipping unnecessary checks.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579:        for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
```
['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue;
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
```
['[706](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L706-L706)']
```solidity
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
709:                 }
```
['[711](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L711-L711)']
```solidity
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]);
714:                 }
```


</details>

## [Gas-22] Where a value is casted more than once, consider caching the result to save gas

### Resolution 
Casting values multiple times in Solidity can be gas-inefficient. When a value undergoes repeated type conversions, the EVM must execute additional operations for each cast, consuming more gas than necessary. To optimize for gas efficiency, cache the result of the initial cast in a local variable and reuse it, rather than performing multiple casts. This not only conserves gas but also enhances code readability, reducing potential error points. For example, instead of repeatedly casting an `address` to `uint256`, cast once, store the result in a local variable, and reference that variable in subsequent operations.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L838)']
```solidity
823:     function onStreamCanceled(
824:         uint256 streamId,
825:         address sender,
826:         uint128 senderAmount,
827:         uint128 
828:     ) external override onlySablier checkEpochRollover {
829:         address streamOwner = _streamIDOwners[streamId];
830: 
831:         if (streamOwner == address(0)) revert StreamOwnerNotFound();
832: 
833:         _redeem(streamOwner);
834: 
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId];
836: 
837:         uint256 amount =
838:             uint256(senderAmount) > nftData.amount ? nftData.amount : uint256(senderAmount); // <= FOUND
839: 
840:         _unstakeVested(streamOwner, streamId, amount);
841: 
842:         emit SablierCanceled(streamOwner, streamId, sender, amount);
843:     }
```
['[823](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L823-L838)']
```solidity
823:     function onStreamCanceled(
824:         uint256 streamId,
825:         address sender,
826:         uint128 senderAmount,
827:         uint128 
828:     ) external override onlySablier checkEpochRollover {
829:         address streamOwner = _streamIDOwners[streamId];
830: 
831:         if (streamOwner == address(0)) revert StreamOwnerNotFound();
832: 
833:         _redeem(streamOwner);
834: 
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId];
836: 
837:         uint256 amount =
838:             uint256(senderAmount) > nftData.amount ? nftData.amount : uint256(senderAmount); // <= FOUND 'int256(senderAmount)'
839: 
840:         _unstakeVested(streamOwner, streamId, amount);
841: 
842:         emit SablierCanceled(streamOwner, streamId, sender, amount);
843:     }
```


</details>

## [Gas-23] Use assembly to validate msg.sender

### Resolution 
Utilizing assembly for validating `msg.sender` can potentially save gas as it allows for more direct and efficient access to Ethereum’s EVM opcodes, bypassing some of the overhead introduced by Solidity’s higher-level abstractions. However, this practice requires deep expertise in EVM, as incorrect implementation can introduce critical vulnerabilities. It is a trade-off between gas efficiency and code safety.

Num of instances: 3

### Findings 


<details><summary>Click to show findings</summary>

['[128](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L128-L128)']
```solidity
128:         if (msg.sender != owner) revert CallerDisallowed(); // <= FOUND
```
['[311](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L311-L311)']
```solidity
311:         if (msg.sender != rewardAdmin) revert CallerDisallowed(); // <= FOUND
```
['[326](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L326-L326)']
```solidity
326:         if (msg.sender != address(sablier)) revert CallerDisallowed(); // <= FOUND
```


</details>

## [Gas-24] Simple checks for zero uint can be done using assembly to save gas

### Resolution 
Using assembly for simple zero checks on unsigned integers can save gas due to lower-level, optimized operations. 

**Resolution**: Implement inline assembly with Solidity's `assembly` block to perform zero checks. Ensure thorough testing and verification, as assembly lacks the safety checks of high-level Solidity, potentially introducing vulnerabilities if not used carefully.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[370](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L370-L371)']
```solidity
370:         
371:         if (_amount == 0) revert InvalidAmount(); // <= FOUND
```
['[370](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L370-L370)']
```solidity
370:         if (_amount == 0) revert InvalidAmount(); // <= FOUND
```
['[648](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L648-L648)']
```solidity
648:         if (rewardAmount == 0) return (0, 0); // <= FOUND
```
['[412](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L412-L412)']
```solidity
412:         if (depositedAmount - (withdrawnAmount + refundedAmount) <= 0) revert InvalidAmount(); // <= FOUND
```


</details>

## [Gas-25] Using nested if to save gas

### Resolution 
Using nested `if` statements instead of logical AND (`&&`) operators can potentially save gas in Solidity contracts. When a series of conditions are connected with `&&`, all conditions must be evaluated even if the first one fails. In contrast, nested `if` statements allow for short-circuiting; if the first condition fails, the rest are skipped, saving gas. This approach is more gas-efficient, especially when dealing with complex or gas-intensive conditions. However, it's crucial to balance gas savings with code readability and maintainability, ensuring that the code remains clear and easy to understand.

Num of instances: 6

### Findings 


<details><summary>Click to show findings</summary>

['[737](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L737-L737)']
```solidity
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch) { // <= FOUND
738:             
739:             DepositReceipt memory deposit = deposits[sender][ud.unredeemedEpoch];
740: 
741:             
742:             ud.unclaimedRewards += calculateReward(
743:                 deposit.staked + deposit.vestedStaked, ud.unredeemedEpoch, currentEpoch - 1
744:             );
745: 
746:             ud.unredeemedEpoch = 0;
747:             ud.totalStaked += (deposit.staked + deposit.vestedStaked);
748:         }
```
['[478](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L478-L478)']
```solidity
478:         if (dr.staked == 0 && dr.vestedStaked == 0) { // <= FOUND
479:             
480:             if (userData[msg.sender].unredeemedEpoch == currentEpoch) {
481:                 userData[msg.sender].unredeemedEpoch = 0;
482:             }
```
['[540](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L540-L540)']
```solidity
540:         if (dr.vestedStaked == 0 && dr.staked == 0) { // <= FOUND
541:             
542:             if (userData[streamOwner].unredeemedEpoch == currentEpoch) {
543:                 userData[streamOwner].unredeemedEpoch = 0;
544:             }
```
['[478](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L478-L478)']
```solidity
478:         if (dr.staked == 0 && dr.vestedStaked == 0) { // <= FOUND
```
['[540](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L540-L540)']
```solidity
540:         if (dr.vestedStaked == 0 && dr.staked == 0) { // <= FOUND
```
['[737](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L737-L737)']
```solidity
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch) { // <= FOUND
```


</details>

## [Gas-26] Optimize Storage with Byte Truncation for Time Related State Variables

### Resolution 
Storage optimization in Solidity contracts is vital for reducing gas costs, especially when storing time-related state variables. Using `uint32` for storing time values like timestamps is often sufficient, given it can represent dates up to the year 2106. By truncating larger default integer types to `uint32`, you significantly save on storage space and consequently on gas costs for deployment and state modifications. However, ensure that the truncation does not lead to overflow issues and that the variable's size is adequate for the application's expected lifespan and precision requirements. Adopting this optimization practice contributes to more efficient and cost-effective smart contract development.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[66](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L66-L66)']
```solidity
66: uint256 public auctionEndTime; // <= FOUND
```
['[265](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L265-L265)']
```solidity
265: uint256 public immutable startTime; // <= FOUND
```
['[250](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L250-L250)']
```solidity
250: uint256 public constant epochDuration = 86_400 * 7;  // <= FOUND
```
['[54](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L54-L54)']
```solidity
54: uint256 public constant EPOCH_DURATION = 1 weeks; // <= FOUND
```


</details>

## [Gas-27] Using delete instead of setting mapping to 0 saves gas

Num of instances: 3

### Findings 


<details><summary>Click to show findings</summary>

['[218](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L218-L218)']
```solidity
218:         bids[msg.sender] = 0; // <= FOUND
```
['[481](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L481-L481)']
```solidity
481:                 userData[msg.sender].unredeemedEpoch = 0; // <= FOUND
```
['[543](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L543-L543)']
```solidity
543:                 userData[streamOwner].unredeemedEpoch = 0; // <= FOUND
```


</details>

## [Gas-28] Stack variable cost less than state variables while used in emiting event

### Resolution 
When emitting events in Solidity, using stack variables (local variables within a function) instead of state variables can lead to significant gas savings. Stack variables reside in memory only for the duration of the function execution and are less costly to access compared to state variables, which are stored on the blockchain. When an event is emitted, accessing these stack variables requires less gas than fetching data from state variables, which involves reading from the contract's storage - a more expensive operation. Thus, for efficiency, prefer using local variables within functions for event emission, especially in functions that are called frequently.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[390](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L390-L390)']
```solidity
390:         emit Staked(msg.sender, currentEpoch, _amount); // <= FOUND
```
['[438](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L438-L438)']
```solidity
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount); // <= FOUND
```
['[190](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L190-L190)']
```solidity
190:         emit AuctionEnded(totalBids, totalTokens); // <= FOUND
```
['[247](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L247-L247)']
```solidity
247:         emit PointsDistributed(pointsPerEpoch, pointsPerToken); // <= FOUND
```
['[639](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L639-L639)']
```solidity
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch); // <= FOUND
```


</details>

## [Gas-29] Stack variable cost less than mappings while used in emiting event

### Resolution 
When emitting events in Solidity, using stack variables (local variables within a function) instead of mappings can lead to significant gas savings. Stack variables reside in memory only for the duration of the function execution and are less costly to access compared to mappings, which are stored on the blockchain. When an event is emitted, accessing these stack variables requires less gas than fetching data from mappings, which involves reading from the contract's storage - a more expensive operation. Thus, for efficiency, prefer using local variables within functions for event emission, especially in functions that are called frequently.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[708](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L708-L708)']
```solidity
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
```


</details>

## [Gas-30] Inline modifiers used only once

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[310](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L310-L310)']
```solidity
310:     modifier onlyRewardAdmin() { // <= FOUND
311:         if (msg.sender != rewardAdmin) revert CallerDisallowed();
312:         _;
313:     }
```


</details>

## [Gas-31] Use s.x = s.x + y instead of s.x += y for memory structs (same for -= etc)

### Resolution 
In Solidity, optimizing gas usage is crucial, particularly for frequently executed operations. For memory structs, using explicit assignment (e.g., `s.x = s.x + y`) instead of shorthand operations (e.g., `s.x += y`) can result in a minor gas saving, around 100 gas. This difference arises from the way the Solidity compiler optimizes bytecode. While such savings might seem small, they can add up in contracts with high transaction volume. This optimization applies to other compound assignment operators like `-=` and `*=` as well. It's a subtle efficiency gain that developers can leverage, especially in complex contracts where every gas unit counts.

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[729](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L729-L747)']
```solidity
729:     function _redeem(address sender) internal { // <= FOUND
730:         
731:         UserData storage ud = userData[sender];
732: 
733:         ud.unclaimedRewards += // <= FOUND
734:             calculateReward(ud.totalStaked, ud.lastClaimedEpoch, currentEpoch - 1);
735:         ud.lastClaimedEpoch = currentEpoch - 1;
736: 
737:         if (ud.unredeemedEpoch > 0 && ud.unredeemedEpoch < currentEpoch) {
738:             
739:             DepositReceipt memory deposit = deposits[sender][ud.unredeemedEpoch];
740: 
741:             
742:             ud.unclaimedRewards += calculateReward( // <= FOUND
743:                 deposit.staked + deposit.vestedStaked, ud.unredeemedEpoch, currentEpoch - 1 // <= FOUND
744:             );
745: 
746:             ud.unredeemedEpoch = 0;
747:             ud.totalStaked += (deposit.staked + deposit.vestedStaked); // <= FOUND
748:         }
749:     }
```


</details>

## [Gas-32] Calling .length in a for loop wastes gas

### Resolution 
Rather than calling .length for an array in a for loop declaration, it is far more gas efficient to cache this length before and use that instead. This will prevent the array length from being called every loop iteration

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579: for (uint16 i = 0; i < activeDeposits.length; i++)  // <= FOUND
```
['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L579)']
```solidity
579: for (uint16 i = 0; i < activeDeposits.length; i++)  // <= FOUND
```


</details>

## [Gas-33] Constructors can be marked as payable to save deployment gas

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[120](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L120-L120)']
```solidity
120:     constructor(
121:         address _fjordPoints,
122:         address _auctionToken,
123:         uint256 _biddingTime,
124:         uint256 _totalTokens
125:     ) {
126:         if (_fjordPoints == address(0)) {
127:             revert InvalidFjordPointsAddress();
128:         }
129:         if (_auctionToken == address(0)) {
130:             revert InvalidAuctionTokenAddress();
131:         }
132:         fjordPoints = ERC20Burnable(_fjordPoints);
133:         auctionToken = IERC20(_auctionToken);
134:         owner = msg.sender;
135:         auctionEndTime = block.timestamp.add(_biddingTime);
136:         totalTokens = _totalTokens;
137:     }
```
['[24](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuctionFactory.sol#L24-L24)']
```solidity
24:     constructor(address _fjordPoints) {
25:         if (_fjordPoints == address(0)) revert InvalidAddress();
26: 
27:         fjordPoints = _fjordPoints;
28:         owner = msg.sender;
29:     }
```
['[118](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordPoints.sol#L118-L118)']
```solidity
118:     constructor() ERC20("BjordBoint", "BJB") {
119:         owner = msg.sender;
120:         lastDistribution = block.timestamp;
121:         pointsPerEpoch = 100 ether;
122:     }
```
['[281](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L281-L281)']
```solidity
281:     constructor(
282:         address _fjordToken,
283:         address _rewardAdmin,
284:         address _sablier,
285:         address _authorizedSablierSender,
286:         address _fjordPoints
287:     ) {
288:         if (
289:             _rewardAdmin == address(0) || _sablier == address(0) || _fjordToken == address(0)
290:                 || _fjordPoints == address(0)
291:         ) revert InvalidZeroAddress();
292: 
293:         startTime = block.timestamp;
294:         owner = msg.sender;
295:         fjordToken = ERC20(_fjordToken);
296:         currentEpoch = 1;
297:         rewardAdmin = _rewardAdmin;
298:         sablier = ISablierV2Lockup(_sablier);
299:         points = IFjordPoints(_fjordPoints);
300:         if (_authorizedSablierSender != address(0)) {
301:             authorizedSablierSenders[_authorizedSablierSender] = true;
302:         }
303:     }
```
['[7](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordToken.sol#L7-L7)']
```solidity
7:     constructor() ERC20("Fjord Foundry", "FJO", 18) {
8:         _mint(msg.sender, 100_000_000 ether);
9:     }
```


</details>

## [Gas-34] Assigning to structs can be more efficient

### Resolution 
Rather defining the struct in a single line, it is more efficient to declare an empty struct and then assign each struct element individually. This can net quite a large gas saving of 130 per instance.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[397](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L397-L429)']
```solidity
397:     function stakeVested(uint256 _streamID) external checkEpochRollover redeemPendingRewards { // <= FOUND
398:         
399:         if (!sablier.isStream(_streamID)) revert NotAStream();
400:         if (sablier.isCold(_streamID)) revert NotAWarmStream();
401: 
402:         
403:         if (!authorizedSablierSenders[sablier.getSender(_streamID)]) {
404:             revert StreamNotSupported();
405:         }
406:         if (address(sablier.getAsset(_streamID)) != address(fjordToken)) revert InvalidAsset();
407: 
408:         uint128 depositedAmount = sablier.getDepositedAmount(_streamID);
409:         uint128 withdrawnAmount = sablier.getWithdrawnAmount(_streamID);
410:         uint128 refundedAmount = sablier.getRefundedAmount(_streamID);
411: 
412:         if (depositedAmount - (withdrawnAmount + refundedAmount) <= 0) revert InvalidAmount();
413: 
414:         uint256 _amount = depositedAmount - (withdrawnAmount + refundedAmount);
415: 
416:         
417:         userData[msg.sender].unredeemedEpoch = currentEpoch;
418: 
419:         DepositReceipt storage dr = deposits[msg.sender][currentEpoch];
420:         if (dr.epoch == 0) {
421:             dr.vestedStaked = _amount;
422:             dr.epoch = currentEpoch;
423: 
424:             _activeDeposits[msg.sender].add(currentEpoch);
425:         } else {
426:             dr.vestedStaked += _amount;
427:         }
428: 
429:         _streamIDs[msg.sender][_streamID] = NFTData({ epoch: currentEpoch, amount: _amount }); // <= FOUND
430:         _streamIDOwners[_streamID] = msg.sender;
431:         newStaked += _amount;
432:         newVestedStaked += _amount;
433: 
434:         
435:         sablier.transferFrom({ from: msg.sender, to: address(this), tokenId: _streamID });
436:         points.onStaked(msg.sender, _amount);
437: 
438:         emit VestedStaked(msg.sender, currentEpoch, _streamID, _amount);
439:     }
```
['[616](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L616-L636)']
```solidity
616:     function claimReward(bool _isClaimEarly)
617:         external
618:         checkEpochRollover
619:         redeemPendingRewards
620:         returns (uint256 rewardAmount, uint256 penaltyAmount)
621:     {
622:         
623:         UserData storage ud = userData[msg.sender];
624: 
625:         
626:         
627:         if (
628:             claimReceipts[msg.sender].requestEpoch > 0
629:                 || claimReceipts[msg.sender].requestEpoch >= currentEpoch - 1
630:         ) revert ClaimTooEarly();
631: 
632:         if (ud.unclaimedRewards == 0) revert NothingToClaim();
633: 
634:         
635:         if (!_isClaimEarly) {
636:             claimReceipts[msg.sender] = // <= FOUND
637:                 ClaimReceipt({ requestEpoch: currentEpoch, amount: ud.unclaimedRewards });
638: 
639:             emit ClaimReceiptCreated(msg.sender, currentEpoch);
640: 
641:             return (0, 0);
642:         }
643: 
644:         rewardAmount = ud.unclaimedRewards;
645:         penaltyAmount = rewardAmount / 2;
646:         rewardAmount -= penaltyAmount;
647: 
648:         if (rewardAmount == 0) return (0, 0);
649: 
650:         totalRewards -= (rewardAmount + penaltyAmount);
651:         userData[msg.sender].unclaimedRewards -= (rewardAmount + penaltyAmount);
652: 
653:         
654:         fjordToken.safeTransfer(msg.sender, rewardAmount);
655: 
656:         emit EarlyRewardClaimed(msg.sender, rewardAmount, penaltyAmount);
657:     }
```


</details>

## [Gas-35] Use OZ Array.unsafeAccess() to avoid repeated array length checks

### Resolution 
The OpenZeppelin Array.unsafeAccess() method is a optimization strategy for Solidity, aimed at reducing gas costs by bypassing automatic length checks on storage array accesses. In Solidity, every access to an array element involves a hidden gas cost due to a length check, ensuring that accesses do not exceed the array bounds. However, if a developer has already verified the array's bounds earlier in the function or knows through logic that the access is safe, directly accessing the array elements without redundant length checks can save gas. This approach requires careful consideration to avoid out-of-bounds errors, as it trades off safety checks for efficiency.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[580](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L580-L580)']
```solidity
580:             uint16 epoch = uint16(activeDeposits[i]); // <= FOUND
```
['[707](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L707-L707)']
```solidity
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken; // <= FOUND
```
['[708](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L708-L708)']
```solidity
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
```
['[712](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L712-L712)']
```solidity
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded]; // <= FOUND
```


</details>

## [Gas-36] State variable read in a loop

### Resolution 
Reading a state variable inside a loop in a smart contract can unnecessarily increase gas consumption, as each read operation from the blockchain state is costly. This inefficiency becomes pronounced in loops with many iterations. To optimize gas usage, it's advisable to read the state variable once before the loop starts, store its value in a local (memory) variable, and then use this local variable within the loop. This approach minimizes the number of state read operations, thereby reducing the gas cost associated with executing the contract function, making the smart contract more efficient and cost-effective to run.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L583)']
```solidity
579:        for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue; // <= FOUND
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
```
['[579](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L579-L583)']
```solidity
579:         for (uint16 i = 0; i < activeDeposits.length; i++) {
580:             uint16 epoch = uint16(activeDeposits[i]);
581:             DepositReceipt storage dr = deposits[msg.sender][epoch];
582: 
583:             if (dr.epoch == 0 || currentEpoch - epoch <= lockCycle) continue; // <= FOUND
584: 
585:             totalStakedAmount += dr.staked;
586: 
587:             
588:             if (dr.vestedStaked == 0) {
589:                 delete deposits[msg.sender][epoch];
590:                 _activeDeposits[msg.sender].remove(epoch);
591:             } else {
592:                 
593:                 dr.staked = 0;
594:             }
595:         }
```


</details>

## [Gas-37] Use uint256(1)/uint256(2) instead of true/false to save gas for changes

### Resolution 
In Solidity, the use of `uint256` values instead of boolean for certain state variables can result in gas savings. This is due to how Ethereum's storage optimization works: changing a variable from `0` to a non-zero value (like flipping `false` to `true`) incurs a higher gas cost compared to modifying an already non-zero value. By using `uint256` with values `1` and `2` instead of `true` and `false`, you avoid the higher cost associated with the `0` to non-zero change, since `1` and `2` are both non-zero. This approach is notably used in OpenZeppelin's `ReentrancyGuard` as a gas optimization technique. However, this should be applied where it makes sense and where gas optimization is critical, as it can decrease code readability.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[189](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L189-L189)']
```solidity
189:         ended = true; // <= FOUND
```
['[301](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L301-L301)']
```solidity
301:             authorizedSablierSenders[_authorizedSablierSender] = true; // <= FOUND
```
['[358](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L358-L358)']
```solidity
358:         authorizedSablierSenders[_address] = true; // <= FOUND
```
['[362](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L362-L362)']
```solidity
362:         if (authorizedSablierSenders[_address]) authorizedSablierSenders[_address] = false; // <= FOUND
```


</details>

## [Gas-38] Avoid emitting events in loops

### Resolution 
Emitting events inside loops can significantly increase gas costs in Ethereum smart contracts, as each event emission consumes gas. This practice can quickly escalate transaction fees, especially with a high number of iterations. To optimize for efficiency and cost, it's advisable to minimize event emissions within loops, possibly aggregating data to emit a single event post-loop or reconsidering the design to reduce looped emissions. This approach helps maintain manageable transaction costs and enhances contract performance.

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[706](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L706-L708)']
```solidity
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
709:                 }
```
['[711](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L711-L713)']
```solidity
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
714:                 }
```
['[706](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L706-L708)']
```solidity
706:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
707:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded] + pendingRewardsPerToken;
708:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
709:                 }
```
['[711](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L711-L713)']
```solidity
711:                 for (uint16 i = lastEpochRewarded + 1; i < currentEpoch; i++) {
712:                     rewardPerToken[i] = rewardPerToken[lastEpochRewarded];
713:                     emit RewardPerTokenChanged(i, rewardPerToken[i]); // <= FOUND
714:                 }
```


</details>

## [Gas-39] Write direct outcome, instead of performing mathematical operations for constant state variables

### Resolution 
In Solidity, it's highly efficient to directly assign constant values to state variables when these values are known at compile time and will not change. This practice avoids unnecessary computational operations and reduces gas costs for deploying and interacting with smart contracts. 

Num of instances: 1

### Findings 


<details><summary>Click to show findings</summary>

['[250](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L250-L250)']
```solidity
250:  uint256 public constant epochDuration = 86_400 * 7;  // <= FOUND
```


</details>

## [Gas-40] Consider pre-calculating the address of address(this) to save gas

### Resolution 
Consider saving the address(this) value within a constant using foundry's script.sol or solady's LibRlp.sol to save gas

Num of instances: 6

### Findings 


<details><summary>Click to show findings</summary>

['[151](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L151-L151)']
```solidity
151:         fjordPoints.transferFrom(msg.sender, address(this), amount); // <= FOUND
```
['[200](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordAuction.sol#L200-L201)']
```solidity
200:         
201:         uint256 pointsToBurn = fjordPoints.balanceOf(address(this)); // <= FOUND
```
['[387](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L387-L388)']
```solidity
387:         
388:         fjordToken.safeTransferFrom(msg.sender, address(this), _amount); // <= FOUND
```
['[435](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L435-L436)']
```solidity
435:         
436:         sablier.transferFrom({ from: msg.sender, to: address(this), tokenId: _streamID }); // <= FOUND
```
['[558](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L558-L558)']
```solidity
558:             sablier.transferFrom({ from: address(this), to: streamOwner, tokenId: _streamID }); // <= FOUND
```
['[699](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L699-L699)']
```solidity
699:                 uint256 currentBalance = fjordToken.balanceOf(address(this)); // <= FOUND
```


</details>

## [Gas-41] Use 'storage' instead of 'memory' for struct/array state variables

### Resolution 
In Solidity, choosing between `memory` and `storage` for variables, especially when dealing with structs or arrays, is crucial for optimizing gas costs. Variables declared as `storage` are pointers to the blockchain data, leading to lower gas consumption when fields are accessed or modified, as they don't require reading the entire structure. In contrast, `memory` variables copy the entire struct or array from `storage`, incurring significant gas costs, especially for large or complex structures. Therefore, use `storage` for state variables or when working within functions to manipulate existing contract data. Reserve `memory` for temporary data or when data needs to be passed to external functions as copies, ensuring efficient use of gas and avoiding unnecessary costs.

Num of instances: 5

### Findings 


<details><summary>Click to show findings</summary>

['[505](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L505-L505)']
```solidity
505:         DepositReceipt memory dr = deposits[msg.sender][data.epoch]; // <= FOUND
```
['[739](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L739-L740)']
```solidity
739:             
740:             DepositReceipt memory deposit = deposits[sender][ud.unredeemedEpoch]; // <= FOUND
```
['[668](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L668-L668)']
```solidity
668:         ClaimReceipt memory cr = claimReceipts[msg.sender]; // <= FOUND
```
['[504](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L504-L505)']
```solidity
504:         
505:         NFTData memory data = _streamIDs[msg.sender][_streamID]; // <= FOUND
```
['[835](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L835-L835)']
```solidity
835:         NFTData memory nftData = _streamIDs[streamOwner][streamId]; // <= FOUND
```


</details>

## [Gas-42] Public functions not called internally

### Resolution 
Public functions that aren't used internally in Solidity contracts should be made external to optimize gas usage and improve contract efficiency. External functions can only be called from outside the contract, and their arguments are directly read from the calldata, which is more gas-efficient than loading them into memory, as is the case for public functions. By using external visibility, developers can reduce gas consumption for external calls and ensure that the contract operates more cost-effectively for users. Moreover, setting the appropriate visibility level for functions also enhances code readability and maintainability, promoting a more secure and well-structured contract design.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[339](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L339-L339)']
```solidity
339:     function getStreamData(address _user, uint256 _streamID) public view returns (NFTData memory) 
```
['[343](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L343-L343)']
```solidity
343:     function getStreamOwner(uint256 _streamID) public view returns (address) 
```


</details>

## [Gas-43] Empty blocks should be removed or emit something

### Resolution 
Empty code blocks (i.e., {}) in a Solidity contract can be harmful as they can lead to ambiguity, misinterpretation, and unintended behavior. When developers encounter empty code blocks, it may be unclear whether the absence of code is intentional or the result of an oversight. This uncertainty can cause confusion during development, testing, and debugging, increasing the likelihood of introducing errors or vulnerabilities. Moreover, empty code blocks may give a false impression of implemented functionality or security measures, creating a misleading sense of assurance. To ensure clarity and maintainability, it is essential to avoid empty code blocks and explicitly document the intended behavior or any intentional omissions.

Num of instances: 2

### Findings 


<details><summary>Click to show findings</summary>

['[792](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L792-L792)']
```solidity
792:     function onStreamWithdrawn(
793:         uint256, 
794:         address, 
795:         address, 
796:         uint128 
797:     ) external override onlySablier {
798:         
799:     }
```
['[809](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L809-L809)']
```solidity
809:     function onStreamRenounced(uint256  ) external override onlySablier {
810:         
811:     }
```


</details>

## [Gas-44] Using named returns for pure and view functions is cheaper than using regular returns

Num of instances: 4

### Findings 


<details><summary>Click to show findings</summary>

['[330](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L330-L332)']
```solidity
330:     function getEpoch(uint256 _timestamp) public view returns (uint16) {
331:         if (_timestamp < startTime) return 0; // <= FOUND
332:         return uint16((_timestamp - startTime) / epochDuration) + 1; // <= FOUND
333:     }
```
['[335](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L335-L336)']
```solidity
335:     function getActiveDeposits(address _user) public view returns (uint256[] memory) {
336:         return _activeDeposits[_user].values(); // <= FOUND
337:     }
```
['[339](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L339-L340)']
```solidity
339:     function getStreamData(address _user, uint256 _streamID) public view returns (NFTData memory) {
340:         return _streamIDs[_user][_streamID]; // <= FOUND
341:     }
```
['[343](https://github.com/Cyfrin/2024-08-fjord/tree/main/src/FjordStaking.sol#L343-L344)']
```solidity
343:     function getStreamOwner(uint256 _streamID) public view returns (address) {
344:         return _streamIDOwners[_streamID]; // <= FOUND
345:     }
```


</details>
