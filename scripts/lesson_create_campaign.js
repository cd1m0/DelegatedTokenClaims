// const { ethers, run } = require('hardhat');
const { ethers, run } = require('hardhat');
const { setTimeout } = require("timers/promises");

async function lesson() {
  const Claimer = await ethers.getContractFactory('DelegatedClaimCampaigns');
  const claimer = Claimer.attach("0x610178dA211FEF7D417bC0e6FeD39F05609AD788");

  const Token = await ethers.getContractFactory('Token');

  const tok = await Token.attach("0x5FbDB2315678afecb367f032d93F642f64180aa3")
  const amount = 10000000;

  await tok.approve(claimer.target, amount);
  campaign = {
    manager: "0xAaaaAaAAaaaAAaAAaAaaaaAAAAAaAaaaAaAaaAA0",
    token: tok.target,
    amount: 10000000,
    start: 0,
    end: 1000000000000000000000000n,
    tokenLockup: 1,
    root: "0x0000000000000000000000000000000000000000000000000000000000000000",
    delegating: false,
  };
  claimLockup = {
    tokenLocker: "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
    start: 0,
    cliff: 0,
    period: 1,
    periods: 2,
  };


  await claimer.createLockedCampaign("0x00000000000000000000000000000001", 
    campaign, claimLockup, 
    "0x0000000000000000000000000000000000000000",
    1)
}

lesson();
