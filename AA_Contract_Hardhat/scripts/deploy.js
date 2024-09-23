async function main() {

    const [deployer] = await ethers.getSigners();

    console.log(
    "Deploying contracts with the account:",
    deployer.address
    );



 const entry = await ethers.getContractFactory("EntryPoint");
    const contractEntry = await entry.deploy();
    console.log("EntryPoint deployed at:", contractEntry.address);

    const AA = await ethers.getContractFactory("SimpleAccountFactory");
    const contract = await AA.deploy(contractEntry.address);

    console.log("Contract deployed at:", contract.address);

}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);

  });


