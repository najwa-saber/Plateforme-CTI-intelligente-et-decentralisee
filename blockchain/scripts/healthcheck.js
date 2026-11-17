// Container health: JSON-RPC answers AND the contract deployment file exists (unless --rpc-only).
const fs = require("fs");
const path = require("path");

const rpc = process.env.HARDHAT_RPC_URL || "http://127.0.0.1:8545";
const file = path.join(process.env.DEPLOYMENTS_DIR || path.join(__dirname, "..", "deployments"), "localhost.json");

fetch(rpc, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
})
  .then((r) => r.json())
  .then((j) => {
    if (!j.result) process.exit(1);
    if (process.argv.includes("--rpc-only")) process.exit(0);
    process.exit(fs.existsSync(file) ? 0 : 1);
  })
  .catch(() => process.exit(1));
