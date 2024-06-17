// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.24;

import './libraries/TransferHelper.sol';
import './interfaces/IVestingPlans.sol';
import './interfaces/ILockupPlans.sol';
import './interfaces/IDelegatePlan.sol';
import './interfaces/IERC20Votes.sol';

import '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';
import '@openzeppelin/contracts/token/ERC721/IERC721.sol';
import '@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol';
import '@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol';
import '@openzeppelin/contracts/utils/cryptography/EIP712.sol';
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '@openzeppelin/contracts/utils/Nonces.sol';

interface IPlan is IERC721Enumerable {
  function votingVaults(uint256 id) external view returns (address vault);
}

library SetList {
  struct SL {
    bytes16[] lst;
    mapping(bytes16 => uint) idxs;
  }

  function add(SL storage s, bytes16 id) internal {
    if (s.idxs[id] != 0) {
      return;
    }

    if (s.lst.length == 0) {
      s.lst.push();
    }

    s.idxs[id] = s.lst.length;
    s.lst.push(id);
  }

  function remove(SL storage s, bytes16 id) internal {
    if (s.idxs[id] == 0) {
      return;
    }

    uint256 idx = s.idxs[id];
    bytes16 last = s.lst[s.lst.length - 1];

    s.lst[idx] = last;
    s.idxs[last] = idx;
    s.lst.pop();
  }
}

/// @title ClaimCampaigns - The smart contract to distribute your tokens to the community via claims
/// @notice This tool allows token projects to safely, securely and efficiently distribute your tokens in large scale to your community, whereby they can claim them based on your criteria of wallet address and amount.
/// #if_succeeds "Manual Invariants" checkManualInvs();
contract DelegatedClaimCampaigns is ERC721Holder, ReentrancyGuard, EIP712, Nonces {
  using SetList for SetList.SL;
  /// @dev this claimhash is used for EIP712 signing of the claim functions
  bytes32 private constant CLAIM_TYPEHASH =
    keccak256('Claim(bytes16 campaignId,address claimer,uint256 claimAmount,uint256 nonce,uint256 expiry)');

  bytes32 private constant MULITCLAIM_TYPEHASH =
    keccak256(
      'MultiClaim(bytes16 campaignId,address claimer,uint256 claimAmount,uint256 nonce,uint256 expiry,uint256 numberOfClaims)'
    );

  bytes32 private constant DELEGATINGCLAIM_TYPEHASH =
    keccak256(
      'DelegatingClaim(bytes16 campaignId,address claimer,uint256 claimAmount,address delegatee,uint256 nonce,uint256 expiry)'
    );

  mapping(address => bool) public tokenLockers;

  SetList.SL campaignGIds;
  SetList.SL claimLockupsIds;
  function checkManualInvs() public view returns (bool) {
    // For all claims the tokenLocker is approved
    for (uint i = 1; i < claimLockupsIds.lst.length; i++) {
      ClaimLockup storage cl = claimLockups[claimLockupsIds.lst[i]];
      if (!tokenLockers[cl.tokenLocker]) {
        return false;
      }
    }

    // For all tokens T in campaigns, the sum of amounts across all campaigns for T equals the balance of this contract
    for (uint i = 1; i < campaignGIds.lst.length; i++) {
      Campaign storage c = campaigns[campaignGIds.lst[i]];
      IERC20 t = IERC20(c.token);
      uint totalAmount = 0;
      for (uint j = 1; j < campaignGIds.lst.length; j++) {
        Campaign storage c1 = campaigns[campaignGIds.lst[j]];
        if (c1.token != address(t)) {
          continue;
        }

        totalAmount += c1.amount;
      }

      if (t.balanceOf(address(this)) != totalAmount) {
        return false;
      }
    }

    // For all locked campaigns the allowance of the token locker is 0
    for (uint i = 1; i < claimLockupsIds.lst.length; i++) {
      ClaimLockup storage cl = claimLockups[claimLockupsIds.lst[i]];
      Campaign storage c = campaigns[claimLockupsIds.lst[i]];

      IERC20 t = IERC20(c.token);
      if (t.allowance(address(this), cl.tokenLocker) != 0) {
        return false;
      }
    }

    return true;
  }

  /// @dev an enum defining the different types of claims to be made
  /// @param Unlocked means that tokens claimed are liquid and not locked at all
  /// @param Locked means that the tokens claimed will be locked inside a TokenLockups plan
  /// @param Vesting means the tokens claimed will be locked inside a TokenVesting plan
  enum TokenLockup {
    Unlocked,
    Locked,
    Vesting
  }

  /// @notice the struct that defines the Locked and Vesting parameters for each vesting
  /// @dev this can be ignored for Unlocked claim campaigns
  /// @param tokenLocker is the address of the TokenLockup or TokenVesting plans contract that will lock the tokens
  /// @param start is the start date when the unlock / vesting begins
  /// @param cliff is the single cliff date for unlocking and vesting plans, when all tokens prior to the cliff remained locked and unvested
  /// @param period is the amount of seconds in each discrete period.
  /// @param periods is the total number of periods that the tokens will be locked or vested for
  struct ClaimLockup {
    address tokenLocker;
    uint256 start;
    uint256 cliff;
    uint256 period;
    uint256 periods;
  }

  /// @notice Campaign is the struct that defines a claim campaign in general. The Campaign is related to a one time use, related to a merkle tree that pre defines all of the wallets and amounts those wallets can claim
  /// once the amount is 0, the campaign is ended. The campaign can also be terminated at any time.
  /// @param manager is the address of the campaign manager who is in charge of cancelling the campaign - AND if the campaign is setup for vesting, this address will be used as the vestingAdmin wallet for all of the vesting plans created
  /// the manager is typically the msg.sender wallet, but can be defined as something else in case.
  /// @param token is the address of the token to be claimed by the wallets, which is pulled into the contract during the campaign
  /// @param amount is the total amount of tokens left in the Campaign. this starts out as the entire amount in the campaign, and gets reduced each time a claim is made
  /// @param start is the start time of the campaign when ppl can begin claiming their tokens
  /// @param end is a unix time that can be used as a safety mechanism to put a hard end date for a campaign, this can also be far far in the future to effectively be forever claims
  /// @param tokenLockup is the enum (uint8) that describes how and if the tokens will be locked or vesting when they are claimed. If set to unlocked, claimants will just get the tokens, but if they are Locked / vesting, they will receive the NFT Tokenlockup plan or vesting plan
  /// @param root is the root of the merkle tree used for the claims.
  /// @param delegating is a boolean defining whether the claims need to be delegated when claimed or not
  struct Campaign {
    address manager;
    address token;
    uint256 amount;
    uint256 start;
    uint256 end;
    TokenLockup tokenLockup;
    bytes32 root;
    bool delegating;
  }

  /// @dev this is for the EIP712 signatures used for claiming tokens on behalf of users
  /// @param nonce is the nonce of the claimer, which is used to prevent replay attacks
  /// @param expiry is the expiry time of the claim, which is used to prevent replay attacks
  /// @param v is the v value of the signature
  /// @param r is the r value of the signature
  /// @param s is the s value of the signature
  struct SignatureParams {
    uint256 nonce;
    uint256 expiry;
    uint8 v;
    bytes32 r;
    bytes32 s;
  }

  /// @dev we use UUIDs or CIDs to map to a specific unique campaign. The UUID or CID is typically generated when the merkle tree is created, and then that id or cid is the identifier of the file in S3 or IPFS
  mapping(bytes16 => Campaign) public campaigns;
  /// @dev the same UUID is maped to the ClaimLockup details for the specific campaign
  mapping(bytes16 => ClaimLockup) public claimLockups;
  /// @dev this maps the UUID that have already been used, so that a campaign cannot be duplicated
  mapping(bytes16 => bool) public usedIds;

  mapping(bytes16 => uint256) private _campaignBlockNumber;

  //maps campaign id to a wallet address, which is flipped to true when claimed
  mapping(bytes16 => mapping(address => bool)) public claimed;

  //maps campaign id to the vesting admin address when the campaign is a vesting campaign
  mapping(bytes16 => address) private _vestingAdmins;

  // events
  event CampaignStarted(bytes16 indexed id, Campaign campaign, uint256 totalClaimers);
  event ClaimLockupCreated(bytes16 indexed id, ClaimLockup claimLockup);
  event CampaignCancelled(bytes16 indexed id);
  event LockedTokensClaimed(
    bytes16 indexed id,
    address indexed claimer,
    uint256 amountClaimed,
    uint256 amountRemaining
  );
  event UnlockedTokensClaimed(
    bytes16 indexed id,
    address indexed claimer,
    uint256 amountClaimed,
    uint256 amountRemaining
  );
  event Claimed(address indexed recipient, uint256 indexed amount);

  /// @notice the constructor of the contract, which sets the name and version of the EIP712 contract
  constructor(string memory name, string memory version, address[] memory _tokenLockups) EIP712(name, version) {
    for (uint256 i = 0; i < _tokenLockups.length; i++) {
      tokenLockers[_tokenLockups[i]] = true;
    }
  }

  /**********EXTERNAL CREATE& CANCEL CLAIMS FUNCTIONS********************************************************************************************/

  /// @notice primary function for creating an unlocked claims campaign. This function will pull the amount of tokens in the campaign struct, and map the campaign to the id.
  /// @dev the merkle tree needs to be pre-generated, so that you can upload the root and the uuid for the function
  /// @param id is the uuid or CID of the file that stores the merkle tree
  /// @param campaign is the struct of the campaign info, including the total amount tokens to be distributed via claims, and the root of the merkle tree
  /// @param totalClaimers is the total number of claimers that can claim from the campaign
  /// #if_succeeds "Campaign id not used; usedIds updated." !old(usedIds[id]) && usedIds[id];
  /// #if_succeeds "Start and end times valid." campaign.end >= block.timestamp && campaign.end > campaign.start;
  /// #if_succeeds "Campaign token and manager non-0; Campaign amount valid and type is unlocked." campaign.token != address(0) && campaign.manager != address(0) && campaign.amount > 0 && campaign.tokenLockup == TokenLockup.Unlocked;
  /// #if_succeeds "Campaign tokens transferred to us." let tok := old(IERC20(campaign.token)) in old(tok.balanceOf(address(this))) + campaign.amount == tok.balanceOf(address(this));
  function createUnlockedCampaign(bytes16 id, Campaign memory campaign, uint256 totalClaimers) external nonReentrant {
    require(!usedIds[id], 'in use');
    require(id != bytes16(0), '0_id');
    usedIds[id] = true;
    require(campaign.token != address(0), '0_address');
    require(campaign.manager != address(0), '0_manager');
    require(campaign.amount > 0, '0_amount');
    require(campaign.end > block.timestamp && campaign.end > campaign.start, 'end error');
    require(campaign.tokenLockup == TokenLockup.Unlocked, 'locked');
    if (campaign.delegating) {
      require(IERC20Votes(campaign.token).delegates(address(this)) == address(0), '!erc20votes');
    }
    TransferHelper.transferTokens(campaign.token, msg.sender, address(this), campaign.amount);
    campaigns[id] = campaign;
    campaignGIds.add(id);
    _campaignBlockNumber[id] = block.number;
    emit CampaignStarted(id, campaign, totalClaimers);
  }

  /// @notice primary function for creating an locked or vesting claims campaign. This function will pull the amount of tokens in the campaign struct, and map the campaign and claimLockup to the id.
  /// additionally it will check that the lockup details are valid, and perform an allowance increase to the contract for when tokens are claimed they can be pulled.
  /// @dev the merkle tree needs to be pre-generated, so that you can upload the root and the uuid for the function
  /// @param id is the uuid or CID of the file that stores the merkle tree
  /// @param campaign is the struct of the campaign info, including the total amount tokens to be distributed via claims, and the root of the merkle tree, plus the lockup type of either 1 (lockup) or 2 (vesting)
  /// @param claimLockup is the struct that defines the characteristics of the lockup for each token claimed.
  /// @param vestingAdmin is the address of the vesting admin, which is used for the vesting plans, and is typically the msg.sender
  /// #if_succeeds "Campaign id not used; usedIds updated." !old(usedIds[id]) && usedIds[id];
  /// #if_succeeds "Start and end times valid." campaign.end >= block.timestamp && campaign.end > campaign.start;
  /// #if_succeeds "Campaign token and manager non-0; Campaign amount valid and type is unlocked." campaign.token != address(0) && campaign.manager != address(0) && campaign.amount > 0 && campaign.tokenLockup != TokenLockup.Unlocked;
  /// #if_succeeds "Token locker is approved" tokenLockers[claimLockup.tokenLocker] && claimLockup.tokenLocker != address(0);
  /// #if_succeeds "If vesting campaign, vestingAdmin is provided." campaign.tokenLockup == TokenLockup.Vesting ==> vestingAdmin != address(0);
  /// #if_succeeds "Campaign tokens transferred to us." let tok := old(IERC20(campaign.token)) in old(tok.balanceOf(address(this))) + campaign.amount == tok.balanceOf(address(this));
  /// #if_succeeds "No allowance given to tokenLocker." let tok := IERC20(campaign.token) in let locker := claimLockup.tokenLocker in tok.allowance(address(this), locker) == 0;
  function createLockedCampaign(
    bytes16 id,
    Campaign memory campaign,
    ClaimLockup memory claimLockup,
    address vestingAdmin,
    uint256 totalClaimers
  ) external nonReentrant {
    require(!usedIds[id], 'in use');
    require(id != bytes16(0), '0_id');
    usedIds[id] = true;
    require(campaign.token != address(0), '0_address');
    require(campaign.manager != address(0), '0_manager');
    require(campaign.amount > 0, '0_amount');
    require(campaign.end > block.timestamp && campaign.end > campaign.start, 'end error');
    require(campaign.tokenLockup != TokenLockup.Unlocked, '!locked');
    require(claimLockup.periods > 0, '0_periods');
    require(claimLockup.period > 0, '0_period');
    require(tokenLockers[claimLockup.tokenLocker], 'invalid locker');
    if (campaign.delegating) {
      require(IERC20Votes(campaign.token).delegates(address(this)) == address(0), '!erc20votes');
    }
    if (campaign.tokenLockup == TokenLockup.Vesting) {
      require(vestingAdmin != address(0), '0_admin');
      _vestingAdmins[id] = vestingAdmin;
    }
    require(claimLockup.tokenLocker != address(0), 'invalide locker');
    TransferHelper.transferTokens(campaign.token, msg.sender, address(this), campaign.amount);
    claimLockups[id] = claimLockup;
    campaigns[id] = campaign;
    campaignGIds.add(id);
    claimLockupsIds.add(id);
    _campaignBlockNumber[id] = block.number;
    emit ClaimLockupCreated(id, claimLockup);
    emit CampaignStarted(id, campaign, totalClaimers);
  }

  /// @notice this function allows the campaign manager to cancel an ongoing campaign at anytime. Cancelling a campaign will return any unclaimed tokens, and then prevent anyone from claiming additional tokens
  /// @param campaignIds is the id of the campaign to be cancelled
  /// #if_succeeds "Only the manager can cancel a campaign." old(forall (uint i in campaignIds) campaigns[campaignIds[i]].manager == msg.sender);
  /// #if_succeeds "For each campaign we didnt give an allowance to the token locker." old(forall (uint i in campaignIds) let id := campaignIds[i] in let c := campaigns[id] in IERC20(c.token).allowance(address(this), claimLockups[id].tokenLocker) == 0);
  /// #try campaignIds.length == 1 && campaignIds[0] == bytes16(uint128(0x00000000000000000000000000000001));`
  /// (checked by contract if_succeeds) afterwards the amounts of tokens for each token type matches the sum of amounts across all campaigns for this token type
  function cancelCampaigns(bytes16[] memory campaignIds) external nonReentrant {
    for (uint256 i = 0; i < campaignIds.length; i++) {
      Campaign memory campaign = campaigns[campaignIds[i]];
      require(campaign.manager == msg.sender, '!manager');
      require(_campaignBlockNumber[campaignIds[i]] < block.number, 'same block');
      require(
        (IERC20(campaign.token).allowance(address(this), claimLockups[campaignIds[i]].tokenLocker)) == 0,
        'allowance error'
      );
      delete campaigns[campaignIds[i]];
      delete claimLockups[campaignIds[i]];
      campaignGIds.remove(campaignIds[i]);
      claimLockupsIds.remove(campaignIds[i]);
      TransferHelper.withdrawTokens(campaign.token, msg.sender, campaign.amount);
      emit CampaignCancelled(campaignIds[i]);
    }
  }

  /***************EXTERNAL CLAIMING FUNCTIONS***************************************************************************************************/

  /// @notice the primary function for claiming tokens from a campaign if there is no delegation requirement
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimAmount is the amount of tokens to claim
  /// @dev the function checks that the claimer has not already claimed, and that the campaign is not delegating, and then calls the internal claim function
  /// #if_succeeds "Can only claim in time window"
  ///     old(let c := campaigns[campaignId] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim." old(!claimed[campaignId][msg.sender]) && claimed[campaignId][msg.sender];
  /// #if_succeeds "Not a delegated camapign." old(!campaigns[campaignId].delegating);
  /// #if_succeeds "We send claimAmout of campaigns token." let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(tok.balanceOf(address(this))) - claimAmount == tok.balanceOf(address(this));
  /// #if_succeeds "Sender gets the tokens on unlocked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(c.tokenLockup == TokenLockup.Unlocked) ==> old(tok.balanceOf(msg.sender)) + claimAmount == tok.balanceOf(msg.sender);
  /// #if_succeeds "Token locker gets the tokens on locked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in let locker := old(claimLockups[campaignId].tokenLocker) in
  ///   old(c.tokenLockup != TokenLockup.Unlocked) ==> old(tok.balanceOf(locker)) + claimAmount == tok.balanceOf(locker);
  /// #if_succeeds "Token locker doesnt have allowance after claim." let c := old(campaigns[campaignId]) in let locker := old(claimLockups[campaignId].tokenLocker) in let tok := old(IERC20(c.token)) in tok.allowance(address(this), locker) == 0;
  function claim(bytes16 campaignId, bytes32[] calldata proof, uint256 claimAmount) external nonReentrant {
    require(!claimed[campaignId][msg.sender], 'already claimed');
    require(!campaigns[campaignId].delegating, 'must delegate');
    if (campaigns[campaignId].tokenLockup == TokenLockup.Unlocked) {
      _claimUnlockedTokens(campaignId, proof, msg.sender, claimAmount);
    } else {
      _claimLockedTokens(campaignId, proof, msg.sender, claimAmount);
    }
  }

  struct TransferDesc {
    IERC20 token;
    uint lost;
    uint oldBalance;
    address[] recipients;
    uint[] amounts;
    uint[] oldRecepientBalances;
  }

  TransferDesc[] tempDescs;

  function computeExpectedTransfers(
    bytes16[] calldata campaignIds,
    uint256[] calldata claimAmounts,
    address claimer
  ) internal returns (TransferDesc[] memory) {
    delete tempDescs;

    for (uint i = 0; i < campaignIds.length; i++) {
      bytes16 b = campaignIds[i];
      Campaign storage c = campaigns[b];

      uint j = 0;
      for (; j < tempDescs.length; j++) {
        if (address(tempDescs[j].token) == c.token) {
          break;
        }
      }

      if (j == tempDescs.length) {
        tempDescs.push();
        tempDescs[j].token = IERC20(c.token);
        tempDescs[j].lost = 0;
        delete tempDescs[j].recipients;
        delete tempDescs[j].amounts;
        delete tempDescs[j].oldRecepientBalances;
      }

      tempDescs[j].lost += claimAmounts[i];
      address recepient = c.tokenLockup == TokenLockup.Unlocked ? claimer : claimLockups[b].tokenLocker;
      uint k = 0;
      for (k = 0; k < tempDescs[j].recipients.length; k++) {
        if (tempDescs[j].recipients[k] == recepient) {
          break;
        }
      }

      if (k == tempDescs[j].recipients.length) {
        tempDescs[j].recipients.push(recepient);
        tempDescs[j].amounts.push(claimAmounts[i]);
      } else {
        tempDescs[j].amounts[k] += claimAmounts[i];
      }
    }

    for (uint i = 0; i < tempDescs.length; i++) {
      TransferDesc storage t = tempDescs[i];
      IERC20 tok = t.token;
      t.oldBalance = tok.balanceOf(address(this));
      for (uint j = 0; j < t.recipients.length; j++) {
        t.oldRecepientBalances.push(tok.balanceOf(t.recipients[j]));
      }
    }

    return tempDescs;
  }

  function checkExpectedTransfers(TransferDesc[] memory tds) internal returns (bool) {
    for (uint i = 0; i < tds.length; i++) {
      TransferDesc storage t = tempDescs[i];
      IERC20 tok = t.token;

      uint curBal = tok.balanceOf(address(this));

      if (curBal + t.lost != t.oldBalance) {
        return false;
      }

      for (uint j = 0; j < t.recipients.length; j++) {
        uint curRecBal = tok.balanceOf(t.recipients[j]);
        if (curRecBal != t.oldRecepientBalances[j] + t.amounts[j]) {
          return false;
        }
      }
    }

    return true;
  }

  /// @notice function to claim tokens from multiple campaigns assuming none of them require delegation
  /// @param campaignIds is the id of the campaign to claim from
  /// @param proofs is the proof of the leaf in the merkle tree
  /// @param claimAmounts is the amount of tokens to claim
  /// #if_succeeds "Can only claim in time window"
  ///   old(forall(uint i in campaignIds)
  ///     let c := campaigns[campaignIds[i]] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim."
  ///   old(forall(uint i in campaignIds) !claimed[campaignIds[i]][msg.sender]) &&
  ///   forall(uint i in campaignIds) claimed[campaignIds[i]][msg.sender];
  /// #if_succeeds "Not a delegated camapign."
  ///   old(forall(uint i in campaignIds) !campaigns[campaignIds[i]].delegating);
  /// Additional checks on balances performed by computeExpectedTransfers/checkExpectedTransfers.
  function claimMultiple(
    bytes16[] calldata campaignIds,
    bytes32[][] calldata proofs,
    uint256[] calldata claimAmounts
  ) external nonReentrant {
    require(campaignIds.length == proofs.length, 'length mismatch');
    require(campaignIds.length == claimAmounts.length, 'length mismatch');

    TransferDesc[] memory tds = computeExpectedTransfers(campaignIds, claimAmounts, msg.sender);
    uint256 claimNum = campaignIds.length;
    for (uint256 i; i < claimNum; ++i) {
      require(!claimed[campaignIds[i]][msg.sender], 'already claimed');
      require(!campaigns[campaignIds[i]].delegating, 'must delegate');
      if (campaigns[campaignIds[i]].tokenLockup == TokenLockup.Unlocked) {
        _claimUnlockedTokens(campaignIds[i], proofs[i], msg.sender, claimAmounts[i]);
      } else {
        _claimLockedTokens(campaignIds[i], proofs[i], msg.sender, claimAmounts[i]);
      }
    }

    if (!checkExpectedTransfers(tds)) {
      revert('Failed expected transfer check in claimMultiple');
    }
  }

  /// @notice function to claim tokens using the EIP712 signature for claiming on behalf of a user
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @param claimSignature is the signature provided by the beneficial owner (the claimer) to the user of the function to claim on their behalf
  /// #if_succeeds "Can only claim in time window"
  ///     old(let c := campaigns[campaignId] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim." old(!claimed[campaignId][claimer]) && claimed[campaignId][claimer];
  /// #if_succeeds "Not a delegated camapign." old(!campaigns[campaignId].delegating);
  /// #if_succeeds "We send claimAmout of campaigns token." let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(tok.balanceOf(address(this))) - claimAmount == tok.balanceOf(address(this));
  /// #if_succeeds "Sender gets the tokens on unlocked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(c.tokenLockup == TokenLockup.Unlocked) ==> old(tok.balanceOf(claimer)) + claimAmount == tok.balanceOf(claimer);
  /// #if_succeeds "Token locker gets the tokens on locked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in let locker := old(claimLockups[campaignId].tokenLocker) in
  ///   old(c.tokenLockup != TokenLockup.Unlocked) ==> old(tok.balanceOf(locker)) + claimAmount == tok.balanceOf(locker);
  /// #if_succeeds "Token locker doesnt have allowance after claim." let c := old(campaigns[campaignId]) in let locker := old(claimLockups[campaignId].tokenLocker) in let tok := old(IERC20(c.token)) in tok.allowance(address(this), locker) == 0;
  /// #if_succeeds "Nonces increase monotonically; Nonces of claimer match signature." nonces(claimer) == old(nonces(claimer)) + 1 && nonces(claimer) == claimSignature.nonce;
  /// #if_succeeds "Signature is correct" ECDSA.recover(
  ///    _hashTypedDataV4(
  ///      keccak256(
  ///        abi.encode(CLAIM_TYPEHASH, campaignId, claimer, claimAmount, claimSignature.nonce, claimSignature.expiry)
  ///      )
  ///    ),
  ///    claimSignature.v,
  ///    claimSignature.r,
  ///    claimSignature.s
  ///  ) == claimer;
  function claimWithSig(
    bytes16 campaignId,
    bytes32[] calldata proof,
    address claimer,
    uint256 claimAmount,
    SignatureParams memory claimSignature
  ) external nonReentrant {
    require(!claimed[campaignId][claimer], 'already claimed');
    require(!campaigns[campaignId].delegating, 'must delegate');
    require(claimSignature.expiry > block.timestamp, 'claim expired');
    address signer = ECDSA.recover(
      _hashTypedDataV4(
        keccak256(
          abi.encode(CLAIM_TYPEHASH, campaignId, claimer, claimAmount, claimSignature.nonce, claimSignature.expiry)
        )
      ),
      claimSignature.v,
      claimSignature.r,
      claimSignature.s
    );
    require(signer == claimer, 'invalid claim signature');
    _useCheckedNonce(claimer, claimSignature.nonce);
    if (campaigns[campaignId].tokenLockup == TokenLockup.Unlocked) {
      _claimUnlockedTokens(campaignId, proof, claimer, claimAmount);
    } else {
      _claimLockedTokens(campaignId, proof, claimer, claimAmount);
    }
  }

  /// add combination of claim with sig and claim multiple
  /// #if_succeeds "Can only claim in time window"
  ///   old(forall(uint i in campaignIds)
  ///     let c := campaigns[campaignIds[i]] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim."
  ///   old(forall(uint i in campaignIds) !claimed[campaignIds[i]][claimer]) &&
  ///   forall(uint i in campaignIds) claimed[campaignIds[i]][claimer];
  /// #if_succeeds "Not a delegated camapign."
  ///   old(forall(uint i in campaignIds) !campaigns[campaignIds[i]].delegating);
  /// #if_succeeds "Nonces increase monotonically; Nonce of claimer matches signature" nonces(claimer) == old(nonces(claimer)) + 1 && nonces(claimer) == claimSignature.nonce;
  /// #if_succeeds "Signature is correct" ECDSA.recover(
  ///    _hashTypedDataV4(
  ///      keccak256(
  ///        abi.encode(MULITCLAIM_TYPEHASH, campaignIds[0], claimer, claimAmounts[0], claimSignature.nonce, claimSignature.expiry)
  ///      )
  ///    ),
  ///    claimSignature.v,
  ///    claimSignature.r,
  ///    claimSignature.s
  ///  ) == claimer;
  function claimMultipleWithSig(
    bytes16[] calldata campaignIds,
    bytes32[][] calldata proofs,
    address claimer,
    uint256[] calldata claimAmounts,
    SignatureParams memory claimSignature
  ) external nonReentrant {
    require(campaignIds.length == proofs.length, 'length mismatch');
    require(campaignIds.length == claimAmounts.length, 'length mismatch');
    require(claimSignature.expiry > block.timestamp, 'claim expired');
    address signer = ECDSA.recover(
      _hashTypedDataV4(
        keccak256(
          abi.encode(
            MULITCLAIM_TYPEHASH,
            campaignIds[0],
            claimer,
            claimAmounts[0],
            claimSignature.nonce,
            claimSignature.expiry,
            campaignIds.length
          )
        )
      ),
      claimSignature.v,
      claimSignature.r,
      claimSignature.s
    );
    require(signer == claimer, 'invalid claim signature');
    _useCheckedNonce(claimer, claimSignature.nonce);
    uint256 claimNum = campaignIds.length;
    TransferDesc[] memory tds = computeExpectedTransfers(campaignIds, claimAmounts, claimer);
    for (uint256 i; i < claimNum; ++i) {
      require(!claimed[campaignIds[i]][claimer], 'already claimed');
      require(!campaigns[campaignIds[i]].delegating, 'must delegate');
      if (campaigns[campaignIds[i]].tokenLockup == TokenLockup.Unlocked) {
        _claimUnlockedTokens(campaignIds[i], proofs[i], claimer, claimAmounts[i]);
      } else {
        _claimLockedTokens(campaignIds[i], proofs[i], claimer, claimAmounts[i]);
      }
    }
    if (!checkExpectedTransfers(tds)) {
      revert('Failed expected transfer check in claimMultiple');
    }
  }

  /// @notice function to claim and delegate tokens in a single transaction. This is required when a claim is delegating, but can also be used for a claim not requiring it, but if the end user wants to claim and delegate in a single transaction
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimAmount is the amount of tokens to claim
  /// @param delegatee is the address of the wallet to delegate the claim to
  /// @param delegationSignature is a signature required Only if the user is claiming unlocked tokens, used to call the delegateWithSig function on the ERC20Votes token contract
  /// @dev the delegation signature is not require and empty entries can be passed in if the campaign is locked or vesting
  /// #if_succeeds "Can only claim in time window"
  ///     old(let c := campaigns[campaignId] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim." old(!claimed[campaignId][msg.sender]) && claimed[campaignId][msg.sender];
  /// #if_succeeds "We send claimAmout of campaigns token." let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(tok.balanceOf(address(this))) - claimAmount == tok.balanceOf(address(this));
  /// #if_succeeds "Sender gets the tokens on unlocked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(c.tokenLockup == TokenLockup.Unlocked) ==> old(tok.balanceOf(msg.sender)) + claimAmount == tok.balanceOf(msg.sender);
  /// #if_succeeds "Voting vault gets the tokens on locked campaigns"
  ///   let c := old(campaigns[campaignId]) in
  ///     let tok := old(IERC20(c.token)) in
  ///       let tokenLocker := old(IPlan(claimLockups[campaignId].tokenLocker)) in
  ///       let tokenId := old(tokenLocker.tokenOfOwnerByIndex(msg.sender, tokenLocker.balanceOf(msg.sender) - 1)) in
  ///       let vault := old(tokenLocker.votingVaults(tokenId)) in
  ///         let oldVaultBalance := old(tok.balanceOf(vault)) in
  ///           let newVaultBalance := tok.balanceOf(vault) in
  ///             old(c.tokenLockup != TokenLockup.Unlocked) ==>  oldVaultBalance + claimAmount == newVaultBalance;
  /// #if_succeeds "Token locker doesnt have allowance after claim." let c := old(campaigns[campaignId]) in let locker := old(claimLockups[campaignId].tokenLocker) in let tok := old(IERC20(c.token)) in tok.allowance(address(this), locker) == 0;
  function claimAndDelegate(
    bytes16 campaignId,
    bytes32[] memory proof,
    uint256 claimAmount,
    address delegatee,
    SignatureParams memory delegationSignature
  ) external nonReentrant {
    require(delegatee != address(0), '0_delegatee');
    require(!claimed[campaignId][msg.sender], 'already claimed');
    if (campaigns[campaignId].tokenLockup == TokenLockup.Unlocked) {
      _claimUnlockedAndDelegate(
        campaignId,
        proof,
        msg.sender,
        claimAmount,
        delegatee,
        delegationSignature.nonce,
        delegationSignature.expiry,
        delegationSignature.v,
        delegationSignature.r,
        delegationSignature.s
      );
    } else {
      _claimLockedAndDelegate(campaignId, proof, msg.sender, claimAmount, delegatee);
    }
  }

  /// @notice function to claim and delegate tokens using the EIP712 signature for claiming on behalf of a user
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @param claimSignature is the signature provided by the beneficial owner (the claimer) to the user of the function to claim on their behalf
  /// @param delegatee is the address of the wallet to delegate the claim to
  /// @param delegationSignature is a signature required Only if the user is claiming unlocked tokens, used to call the delegateWithSig function on the ERC20Votes token contract
  /// @dev the delegation signature is not require and empty entries can be passed in if the campaign is locked or vesting
  /// #if_succeeds "Can only claim in time window"
  ///     old(let c := campaigns[campaignId] in
  ///       c.start <= block.timestamp && block.timestamp <= c.end);
  /// #if_succeeds "Can't double claim." old(!claimed[campaignId][claimer]) && claimed[campaignId][claimer];
  /// #if_succeeds "We send claimAmout of campaigns token." let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(tok.balanceOf(address(this))) - claimAmount == tok.balanceOf(address(this));
  /// #if_succeeds "Claimer gets the tokens on unlocked campaigns" let c := old(campaigns[campaignId]) in let tok := old(IERC20(c.token)) in
  ///   old(c.tokenLockup == TokenLockup.Unlocked) ==> old(tok.balanceOf(claimer)) + claimAmount == tok.balanceOf(claimer);
  /// #if_succeeds "Voting vault gets the tokens on locked campaigns"
  ///   let c := old(campaigns[campaignId]) in
  ///     let tok := old(IERC20(c.token)) in
  ///       let tokenLocker := old(IPlan(claimLockups[campaignId].tokenLocker)) in
  ///       let tokenId := old(tokenLocker.tokenOfOwnerByIndex(claimer, tokenLocker.balanceOf(claimer) - 1)) in
  ///       let vault := old(tokenLocker.votingVaults(tokenId)) in
  ///         let oldVaultBalance := old(tok.balanceOf(vault)) in
  ///           let newVaultBalance := tok.balanceOf(vault) in
  ///             old(c.tokenLockup != TokenLockup.Unlocked) ==>  oldVaultBalance + claimAmount == newVaultBalance;
  /// #if_succeeds "Token locker doesnt have allowance after claim." let c := old(campaigns[campaignId]) in let locker := old(claimLockups[campaignId].tokenLocker) in let tok := old(IERC20(c.token)) in tok.allowance(address(this), locker) == 0;
  function claimAndDelegateWithSig(
    bytes16 campaignId,
    bytes32[] memory proof,
    address claimer,
    uint256 claimAmount,
    SignatureParams memory claimSignature,
    address delegatee,
    SignatureParams memory delegationSignature
  ) external nonReentrant {
    require(delegatee != address(0), '0_delegatee');
    require(!claimed[campaignId][claimer], 'already claimed');
    require(claimSignature.expiry > block.timestamp, 'claim expired');
    address signer = ECDSA.recover(
      _hashTypedDataV4(
        keccak256(
          abi.encode(
            DELEGATINGCLAIM_TYPEHASH,
            campaignId,
            claimer,
            claimAmount,
            delegatee,
            claimSignature.nonce,
            claimSignature.expiry
          )
        )
      ),
      claimSignature.v,
      claimSignature.r,
      claimSignature.s
    );
    require(signer == claimer, 'invalid claim signature');
    _useCheckedNonce(claimer, claimSignature.nonce);
    if (campaigns[campaignId].tokenLockup == TokenLockup.Unlocked) {
      _claimUnlockedAndDelegate(
        campaignId,
        proof,
        claimer,
        claimAmount,
        delegatee,
        delegationSignature.nonce,
        delegationSignature.expiry,
        delegationSignature.v,
        delegationSignature.r,
        delegationSignature.s
      );
    } else {
      _claimLockedAndDelegate(campaignId, proof, claimer, claimAmount, delegatee);
    }
  }

  /*****INTERNAL CLAIMINIG FUNCTIONS**********************************************************************************************/

  /// @notice internal function to claim unlocked tokens without delegation
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @dev the function assumes that signature validation has already been completed, so no need to check that the one claiming is the claimer - as tokens will be delivered to the claimer regardless
  /// the function checks that the campaign has started, that it has not ended, that the proof is valid with the inputs of root, proof, claimer, and claim amount
  /// it checks that the campaign is funded - though this require statement should never be triggered its here as an extra layer of security
  /// it checks that the token lockup type is unlocked
  /// then the function will set the claimed mapping to true so that the claimer cannot claim again
  /// it will reduce the amount of tokens in the campaign by the claim amount
  /// if the campaign amount is 0, then the campaign is deleted as it is complete and over
  /// then the tokens are transferred to the claimer
  function _claimUnlockedTokens(
    bytes16 campaignId,
    bytes32[] memory proof,
    address claimer,
    uint256 claimAmount
  ) internal returns (address token) {
    Campaign memory campaign = campaigns[campaignId];
    require(campaign.start <= block.timestamp, '!started');
    require(campaign.end > block.timestamp, 'campaign ended');
    require(verify(campaign.root, proof, claimer, claimAmount), '!eligible');
    require(campaign.amount >= claimAmount, 'campaign unfunded');
    require(campaign.tokenLockup == TokenLockup.Unlocked, '!unlocked');
    claimed[campaignId][claimer] = true;
    campaigns[campaignId].amount -= claimAmount;
    if (campaigns[campaignId].amount == 0) {
      delete campaigns[campaignId];
      campaignGIds.remove(campaignId);
    }
    TransferHelper.withdrawTokens(campaign.token, claimer, claimAmount);
    emit UnlockedTokensClaimed(campaignId, claimer, claimAmount, campaigns[campaignId].amount);
    return campaign.token;
  }

  /// @notice internal function to claim unlocked tokens and delegate
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @param delegatee is the address of the wallet to delegate the claim to
  /// @param nonce is the nonce of the claimer, which is used to prevent replay attacks
  /// @param expiry is the expiry time of the claim, which is used to prevent replay attacks
  /// @param v is the v value of the signature
  /// @param r is the r value of the signature
  /// @param s is the s value of the signature
  /// @dev this function calls the above internal function to claimUnlockedTokens and then now that the tokens are in the claimers wallet
  /// it uses the delegatebySig function on ERC20Votes to delegate the claimers wallet to the delegatee
  /// it checks that the actual delegation was completed correctly and reverts if not
  /// @dev if the token does not conform to the ERC20Votes interface with the delegateBySig function then it will revert
  function _claimUnlockedAndDelegate(
    bytes16 campaignId,
    bytes32[] memory proof,
    address claimer,
    uint256 claimAmount,
    address delegatee,
    uint256 nonce,
    uint256 expiry,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) internal {
    address token = _claimUnlockedTokens(campaignId, proof, claimer, claimAmount);
    address delegatedTo = IERC20Votes(token).delegates(claimer);
    if (delegatedTo != delegatee) {
      IERC20Votes(token).delegateBySig(delegatee, nonce, expiry, v, r, s);
      delegatedTo = IERC20Votes(token).delegates(claimer);
      require(delegatedTo == delegatee, 'delegation failed');
    }
    emit Claimed(claimer, claimAmount);
  }

  /// @notice internal function to claim locked tokens without delegation
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @dev the function checks that the campaign has started, that it has not ended, that the proof is valid with the inputs of root, proof, claimer, and claim amount
  /// it checks that the campaign is funded - though this require statement should never be triggered its here as an extra layer of security, and then it reduces the campaign amount by the claim amount
  /// if the campaign amount is 0, then the campaign is deleted as it is complete and over
  /// the function calculates the rate to be used for the lockup or vesting plan based on the number of periods and the claim amount
  /// then it creates a lockup plan or vesting plan based on the tokenLockup type in the campaign struct
  function _claimLockedTokens(
    bytes16 campaignId,
    bytes32[] memory proof,
    address claimer,
    uint256 claimAmount
  ) internal {
    Campaign memory campaign = campaigns[campaignId];
    ClaimLockup memory c = claimLockups[campaignId];
    require(campaign.start <= block.timestamp, '!started');
    require(campaign.end > block.timestamp, 'campaign ended');
    require(verify(campaign.root, proof, claimer, claimAmount), '!eligible');
    require(campaign.amount >= claimAmount, 'campaign unfunded');
    claimed[campaignId][claimer] = true;
    campaigns[campaignId].amount -= claimAmount;
    if (campaigns[campaignId].amount == 0) {
      delete campaigns[campaignId];
      delete claimLockups[campaignId];
      campaignGIds.remove(campaignId);
      claimLockupsIds.remove(campaignId);
    }
    uint256 rate;
    if (claimAmount % c.periods == 0) {
      rate = claimAmount / c.periods;
    } else {
      rate = claimAmount / c.periods + 1;
    }
    uint256 start = c.start == 0 ? block.timestamp : c.start;
    uint256 tokenId;
    SafeERC20.safeIncreaseAllowance(IERC20(campaign.token), c.tokenLocker, claimAmount);
    if (campaign.tokenLockup == TokenLockup.Locked) {
      tokenId = ILockupPlans(c.tokenLocker).createPlan(
        claimer,
        campaign.token,
        claimAmount,
        start,
        c.cliff,
        rate,
        c.period
      );
    } else {
      tokenId = IVestingPlans(c.tokenLocker).createPlan(
        claimer,
        campaign.token,
        claimAmount,
        start,
        c.cliff,
        rate,
        c.period,
        _vestingAdmins[campaignId],
        true
      );
    }
    require((IERC20(campaign.token).allowance(address(this), c.tokenLocker)) == 0, 'allowance error');
    emit LockedTokensClaimed(campaignId, claimer, claimAmount, campaigns[campaignId].amount);
  }

  /// @notice internal function to claim locked tokens and delegate
  /// @param campaignId is the id of the campaign to claim from
  /// @param proof is the proof of the leaf in the merkle tree
  /// @param claimer is the address of the beneficial owner of the claim
  /// @param claimAmount is the amount of tokens to claim
  /// @param delegatee is the address of the wallet to delegate the claim to
  /// @dev the function checks that the campaign has started, that it has not ended, that the proof is valid with the inputs of root, proof, claimer, and claim amount
  /// it checks that the campaign is funded - though this require statement should never be triggered its here as an extra layer of security
  /// it checks that the token is an ERC20Votes type token to save gas if it is not
  /// it sets the claimed mapping to true so that the claimer cannot claim again
  /// it reduces the campaign amount by the claim amount
  /// if the campaign amount is 0, then the campaign is deleted as it is complete and over
  /// the function calculates the rate to be used for the lockup or vesting plan based on the number of periods and the claim amount
  /// then it creates a lockup plan or vesting plan based on the tokenLockup type in the campaign struct.
  /// the lockup or vesting plan is issued to this contract address - since only the owner can delegate the plan, and then it delegates the plan to the delegatee
  /// after delegation is complete, then it transfers the plan to the claimer
  /// and for vesting it transfers the vesting admin to the vesting admin
  function _claimLockedAndDelegate(
    bytes16 campaignId,
    bytes32[] memory proof,
    address claimer,
    uint256 claimAmount,
    address delegatee
  ) internal {
    Campaign memory campaign = campaigns[campaignId];
    ClaimLockup memory c = claimLockups[campaignId];
    require(campaign.start <= block.timestamp, '!started');
    require(campaign.end > block.timestamp, 'campaign ended');
    require(verify(campaign.root, proof, claimer, claimAmount), '!eligible');
    require(campaign.amount >= claimAmount, 'campaign unfunded');
    claimed[campaignId][claimer] = true;
    campaigns[campaignId].amount -= claimAmount;
    if (campaigns[campaignId].amount == 0) {
      delete campaigns[campaignId];
      delete claimLockups[campaignId];
      campaignGIds.remove(campaignId);
      claimLockupsIds.remove(campaignId);
    }
    uint256 rate;
    if (claimAmount % c.periods == 0) {
      rate = claimAmount / c.periods;
    } else {
      rate = claimAmount / c.periods + 1;
    }
    uint256 start = c.start == 0 ? block.timestamp : c.start;
    uint256 tokenId;
    SafeERC20.safeIncreaseAllowance(IERC20(campaign.token), c.tokenLocker, claimAmount);
    if (campaign.tokenLockup == TokenLockup.Locked) {
      tokenId = ILockupPlans(c.tokenLocker).createPlan(
        address(this),
        campaign.token,
        claimAmount,
        start,
        c.cliff,
        rate,
        c.period
      );
      IDelegatePlan(c.tokenLocker).delegate(tokenId, delegatee);
      IERC721(c.tokenLocker).transferFrom(address(this), claimer, tokenId);
    } else {
      tokenId = IVestingPlans(c.tokenLocker).createPlan(
        address(this),
        campaign.token,
        claimAmount,
        start,
        c.cliff,
        rate,
        c.period,
        address(this),
        true
      );
      IDelegatePlan(c.tokenLocker).delegate(tokenId, delegatee);
      IERC721(c.tokenLocker).transferFrom(address(this), claimer, tokenId);
      IVestingPlans(c.tokenLocker).changeVestingPlanAdmin(tokenId, _vestingAdmins[campaignId]);
    }
    require((IERC20(campaign.token).allowance(address(this), c.tokenLocker)) == 0, 'allowance error');
    emit Claimed(claimer, claimAmount);
    emit LockedTokensClaimed(campaignId, claimer, claimAmount, campaigns[campaignId].amount);
  }

  /// @dev the internal verify function from the open zepellin library.
  /// this function inputs the root, proof, wallet address of the claimer, and amount of tokens, and then computes the validity of the leaf with the proof and root.
  /// @param root is the root of the merkle tree
  /// @param proof is the proof for the specific leaf
  /// @param claimer is the address of the claimer used in making the leaf
  /// @param amount is the amount of tokens to be claimed, the other piece of data in the leaf
  function verify(bytes32 root, bytes32[] memory proof, address claimer, uint256 amount) public pure returns (bool) {
    bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(claimer, amount))));
    require(MerkleProof.verify(proof, root, leaf), 'Invalid proof');
    return true;
  }
}
