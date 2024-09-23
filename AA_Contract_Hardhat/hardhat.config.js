/** @type import('hardhat/config').HardhatUserConfig */

require("@nomiclabs/hardhat-waffle");

const endpointUrl = "https://polygon-amoy.drpc.org";
const privateKey = "0x7c6cc1af7650ed6c47e5818c76a7af4c631e4c3cfc6b50a487a3ed03ce8ddd31";

module.exports = {
  solidity: "0.8.21",
  networks: {
    amoy: {
      url: endpointUrl,
      accounts: [privateKey],
    },
  },

};

