# Smart Contract Project - HW02

This project contains a smart contract and scripts to deploy and interact with it. Below are the steps to compile, deploy, and interact with the contract.

## Prerequisites

- Node.js and npm installed
- Hardhat installed (`npm install --save-dev hardhat`)
- A valid `.env` file with the following variables:
  - `API_URL`
  - `API_KEY`
  - `PRIVATE_KEY`
  - `CONTRACT_ADDRESS`

## Commands

1. **Compile the Smart Contract**  
   Run the following command to compile the smart contract:
   ```bash
   npx hardhat compile
   ```

2. **Deploy the Smart Contract**  
   Use the following command to deploy the contract to the Sepolia network:
   ```bash
   npx hardhat run scripts/deploy.js --network sepolia
   ```

3. **Interact with the Smart Contract**  
   Execute the script to interact with the deployed contract:
   ```bash
   npx hardhat run scripts/interact.js
   ```

## Notes

- Ensure your `.env` file is correctly configured before running the commands.
- Replace `sepolia` with your desired network if deploying to a different blockchain.

## Folder Structure

- `contracts/`: Contains the smart contract code.
- `scripts/`: Contains deployment and interaction scripts.
- `.env`: Environment variables for API keys and private keys.
