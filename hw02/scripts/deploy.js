async function main() {
    const Poetry = await ethers.getContractFactory("PoetryNFT");

    // Start deployment, returning a promise that resolves to a contract object
    const poetry = await Poetry.deploy();

    await poetry.waitForDeployment();

    console.log("Poetry deployed at", poetry.target);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });