const { ethers, run } = require('hardhat');
const { setTimeout } = require('timers/promises');

// 10 ^ 24
const alot = 1000000000000000000000000n
const rich_attackers = ["0xAaAaaAAAaAaaAaAaAaaAAaAaAAAAAaAAAaaAaAa2", "0xAaaaAaAAaaaAAaAAaAaaaaAAAAAaAaaaAaAaaAA0", "0xafFEaFFEAFfeAfFEAffeaFfEAfFEaffeafFeAFfE"];

async function dpl(name, args) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();

  console.error(`Deployed ${name} to ${contract.target}`);

  return contract;
}

async function deployTokens() {
  const res = [];

  for (const [name, args] of [
      ['Token', ['VT', alot, 3]],
      ['NonVotingToken', ['NVT', alot]],
    ]) {
      const tok = await dpl(name, [name, ...args]);

      for (let richie of rich_attackers) {
        const amt = alot / 10n;
        console.error(`Giving ${richie} ${amt} of token ${name}`)
        await tok.transfer(richie, amt);
      }
    
      res.push();
  }


  return res;
}

async function deployPlans() {
  const res = [];

  for (const [name, abbrev] of [
      ['VotingTokenLockupPlans', 'VTL'],
      ['VotingTokenVestingPlans', 'VTV'],
    ]) {
    res.push(await dpl(name, [name, abbrev]));
  }

  return res;
}

async function deployAll() {
  const [votingToken, nonVotingToken] = await deployTokens();
  const [votingTokenLockupPlan, votingTokenVestingPlans] = await deployPlans();

  const lockers = [votingTokenLockupPlan, votingTokenVestingPlans]

  await dpl('DelegatedClaimCampaigns', ['ClaimCampaigns', '1', lockers]);
}

deployAll();
