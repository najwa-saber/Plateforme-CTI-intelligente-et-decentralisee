#!/bin/sh
# Starts the Hardhat JSON-RPC node, deploys CTIValidation and registers A, B, C.
# NOTE: the Hardhat network is in-memory: restarting this container resets the chain
# (the deployment file is rewritten; reset the application database as well - see docs).
set -e
rm -f "${DEPLOYMENTS_DIR:-/deployments}/localhost.json"
npx hardhat node --hostname 0.0.0.0 --port 8545 &
NODE_PID=$!
for i in $(seq 1 60); do
  if node /app/scripts/healthcheck.js --rpc-only 2>/dev/null; then break; fi
  sleep 1
done
npx hardhat run scripts/deploy.js --network localhost
wait $NODE_PID
