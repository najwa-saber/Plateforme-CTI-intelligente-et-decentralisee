# Local Ethereum network (Hardhat) + automatic deployment of CTIValidation
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee

WORKDIR /app
COPY blockchain/package.json blockchain/package-lock.json /app/
RUN npm ci --no-audit --no-fund --loglevel=error

COPY blockchain/hardhat.config.js /app/
COPY blockchain/contracts /app/contracts
COPY blockchain/scripts /app/scripts
COPY blockchain/test /app/test
# Compile at build time (downloads solc 0.8.24 once)
RUN npx hardhat compile && sed -i 's/\r$//' /app/scripts/start-node.sh && chmod +x /app/scripts/start-node.sh \
    && mkdir -p /deployments

ENV DEPLOYMENTS_DIR=/deployments HARDHAT_RPC_URL=http://127.0.0.1:8545
EXPOSE 8545
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=10 \
    CMD node /app/scripts/healthcheck.js
CMD ["/app/scripts/start-node.sh"]
