// Deploys CTIValidation on the local Hardhat network and registers organisations A, B and C.
// Account 0 = consortium administrator (owner), accounts 1..3 = organisations (configurable).
// Output: deployments/<network>.json (address + ABI) consumed by the FastAPI backend (Web3.py).
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const signers = await hre.ethers.getSigners();
  const owner = signers[0];
  const orgs = [
    { code: "A", name: process.env.ORG_A_NAME || "Organisation A", index: Number(process.env.ORG_A_ACCOUNT_INDEX || 1) },
    { code: "B", name: process.env.ORG_B_NAME || "Organisation B", index: Number(process.env.ORG_B_ACCOUNT_INDEX || 2) },
    { code: "C", name: process.env.ORG_C_NAME || "Organisation C", index: Number(process.env.ORG_C_ACCOUNT_INDEX || 3) },
  ];

  const Factory = await hre.ethers.getContractFactory("CTIValidation");
  const contract = await Factory.deploy(owner.address);
  await contract.waitForDeployment();
  const deployTx = contract.deploymentTransaction();
  const receipt = await deployTx.wait();
  const address = await contract.getAddress();
  console.log(`CTIValidation deployed at ${address} (block ${receipt.blockNumber})`);

  const period = Number(process.env.VOTING_PERIOD_SECONDS || 7 * 24 * 3600);
  if (period !== 7 * 24 * 3600) {
    await (await contract.setVotingPeriod(period)).wait();
    console.log(`voting period set to ${period}s`);
  }

  for (const org of orgs) {
    const account = signers[org.index];
    await (await contract.registerOrganization(account.address, org.name)).wait();
    org.address = account.address;
    console.log(`registered ${org.code} (${org.name}) -> ${account.address}`);
  }

  const artifact = await hre.artifacts.readArtifact("CTIValidation");
  const network = await hre.ethers.provider.getNetwork();
  const out = {
    contract: "CTIValidation",
    network: hre.network.name,
    chainId: Number(network.chainId),
    address,
    owner: owner.address,
    deploymentTx: deployTx.hash,
    deploymentBlock: receipt.blockNumber,
    deployedAt: new Date().toISOString(),
    votingPeriod: period,
    organizations: orgs.map(({ code, name, address: addr, index }) => ({ code, name, address: addr, accountIndex: index })),
    abi: artifact.abi,
  };
  const dir = process.env.DEPLOYMENTS_DIR || path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${hre.network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  console.log(`deployment written to ${file}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
