require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun" },
  },
  networks: {
    hardhat: { chainId: 31337 },
    localhost: { url: process.env.HARDHAT_RPC_URL || "http://127.0.0.1:8545", chainId: 31337 },
  },
  gasReporter: { enabled: process.env.REPORT_GAS === "true", currency: "USD" },
};
