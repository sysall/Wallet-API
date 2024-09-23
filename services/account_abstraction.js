const Web3 = require("web3");
const axios = require("axios");
const web3_utils = require("web3-utils");
var Tx = require('ethereumjs-tx').Transaction
const web3 = new Web3(
    new Web3.providers.HttpProvider("https://rpc-amoy.polygon.technology/")
);

const Account_Factory = require("../services/abi/account_Factory")
const Simple_Account = require("../services/abi/simple_Account")
const ERC20 = require("../services/abi/ERC20")
const ERC721 = require("../services/abi/ERC721")

const FACTORY_CONTRACT = process.env.FACTORY_CONTRACT
const PVT = process.env.PVT_KEY


const MainService = {

    createAccount: async (ownerAddress, salt) => {
        try {
            const contract = new web3.eth.Contract(Account_Factory, FACTORY_CONTRACT);


            // Create the transaction data
            const txData = await contract.methods.createAccount(ownerAddress, salt).encodeABI();
            const txData_gas = await contract.methods.createAccount(ownerAddress, salt).estimateGas()
            console.log("----------------->", txData_gas)
            console.log("txData============>", txData);

            // Create the transaction object
            let signedTx = await web3.eth.accounts.signTransaction({
                "to": FACTORY_CONTRACT,
                "gas": txData_gas,
                "data": txData,
            }, PVT)
            console.log("_-----_--------_-->", signedTx)
            // Send the transaction
            const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction)

            const address = await contract.methods.getAddress(ownerAddress, salt).call();


            console.log('Resulting Address:', address);
            let output = {
                status: 200,
                data: address,
            };
            console.log('Resulting:', receipt);
            return output;
        } catch (error) {
            console.log(error);
            return { status: 500, error: "Something went wrong. Try again later.", };

        }
    },

    // =====> if frontend handles <=======

    // createAccount: async (ownerAddress, salt) => {
    //     try {
    //         const contract = new web3.eth.Contract(Account_Factory, FACTORY_CONTRACT);

    //         const address = await contract.methods.getAddress(ownerAddress, salt.toString()).call();

    //         console.log('Resulting Address:', address);
    //         let output = {
    //             status: 200,
    //             data: address,
    //         };
    //         console.log('Resulting:', address);
    //         return output;
    //     } catch (error) {
    //         console.log(error);
    //         return { status: 500, error: "Something went wrong. Try again later.", };

    //     }
    // },


    deposit: async (ownerAddress, salt) => {
        try {
            const contract = new web3.eth.Contract(Account_Factory, FACTORY_CONTRACT);

            const address = await contract.methods.getAddress(ownerAddress, salt.toString()).call();

            console.log('Resulting Address:', address);
            let output = {
                status: 200,
                data: address,
            };
            console.log('Resulting:', address);
            return output;
        } catch (error) {
            console.log(error);
            return { status: 500, error: "Something went wrong. Try again later.", };

        }
    },

    getBalance: async (address, coin) => {
        try {

            if (coin.type == 'COIN') {
                var balance = await web3.eth.getBalance(address);
                var bal = {
                    name: coin.name,
                    asset: coin.asset,
                    type: coin.type,
                    network: coin.network,
                    balance: (balance / Math.pow(10, coin.decimals)),
                };
                return {
                    status: 200,
                    data: bal
                }
            } else if (coin.type == 'ERC-20' && coin.network == 'MATIC') {


                const contract = new web3.eth.Contract(ERC20, coin.contractAddress);
                const balance = await contract.methods.balanceOf(address).call();

                var bal = {
                    name: coin.name,
                    asset: coin.asset,
                    type: coin.type,
                    network: coin.network,
                    balance: (balance / Math.pow(10, coin.decimals)),

                };
                return {
                    status: 200,
                    data: bal
                }
            }
            else if (coin.type == 'ERC-721' && coin.network == 'MATIC') {


                const contract = new web3.eth.Contract(ERC721, coin.contractAddress);
                const balance = await contract.methods.balanceOf(address).call();
                var bal = {
                    name: coin.name,
                    asset: coin.asset,
                    type: coin.type,
                    network: coin.network,
                    balance: (balance),

                };
                return {
                    status: 200,
                    data: bal
                }
            }
            else {
                return {
                    status: 500
                }
            }


        } catch (error) {
            console.error('Error fetching balance:', error);
        }
    },
    sendAmount: async (fromAddress, toAddress, amount, token_contract_address, walletAddress) => {
        try {

            const contract = new web3.eth.Contract(ERC20, token_contract_address);
            // Create the transaction data
            // const amt = amount.web3.utils.toWei('0.1', 'eth')

            // Call the decimals function
            const decimals = await contract.methods.decimals().call();
            console.log(`Decimals: ${decimals}`);

            const amt = amount * (10 ** decimals)

            console.log("----", amt)
            const txData = await contract.methods.transfer(toAddress, amt).encodeABI({ from: fromAddress });

            console.log("=============================>", txData);

            console.log("Transaction")

            const contract1 = new web3.eth.Contract(Simple_Account, fromAddress);
            console.log("contract1===========>", fromAddress)
            const q = await contract1.methods.owner().call()
            console.log("q===========>", q, walletAddress)
            const data = txData.toString();
            console.log("data===========>", data)
            console.log("fromAddress===========>", fromAddress)
            // web3.eth.accounts.wallet.add({ privateKey: PVT })
            // const execute = await contract1.methods.execute(token_contract_address, '0', data).send({ from: walletAddress, gasLimit: 13000000 });

            // transaction 2


            const amt1 = web3.utils.toWei('0.001', 'ether')




            var rawTx = {
                from: fromAddress,
                gas: web3.utils.toHex(2000000),
                to: walletAddress,
                value: web3.utils.toHex(amt1)
            }

            var tx1 = new Tx(rawTx);
            var serializedTx = tx1.serialize();





            const data1 = '0x' + serializedTx.toString('hex');

            console.log("================================", data1);
            const address = [token_contract_address, walletAddress]
            const amounts = [0, amt1]
            const datas = [data, data1]
            const execute = await contract1.methods.executeBatch(address, amounts, datas).encodeABI();
            console.log("execute")
            // const execute_gas = await contract1.methods.executeBatch(address, amounts, datas).estimateGas({ from: walletAddress })
            // console.log("executevvvvvv")
            // //
            // console.log("------------------------->", execute_gas)
            // console.log("===========================>", execute)
            // Sign the transaction
            let signedTx = await web3.eth.accounts.signTransaction({
                "to": fromAddress,
                "gas": 300000,
                "data": execute,
            }, PVT);
            // const signedTx = await web3.eth.accounts.signTransaction(execute, PVT);
            console.log("=========>", signedTx)

            // Send the transaction
            const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
            console.log("==============>", receipt)

            console.log('Transaction successful with hash:', receipt.transactionHash);
            console.log('Transfer status:', receipt.status ? 'Success' : 'Failure');
            let output = {
                status: 200,
                data: receipt.transactionHash,
            };
            console.log('Resulting:', receipt);
            return output;
        } catch (error) {
            console.log(error);
            if (
                error.message &&
                error.message.includes("insufficient funds for gas")
            ) {
                return {
                    status: 500,
                    error: "Insufficient balance",
                };
            } else {
                return {
                    status: 500,
                    // error: error.message ? error.message : error,
                    error: "Something went wrong. Try again later.",
                };
            }
        }
    },
    sendMatic: async (fromAddress, toAddress, amount, walletAddress) => {

        console.log("==========", fromAddress, toAddress, amount, walletAddress)
        try {
            /// transaction 1
            const amt = web3.utils.toWei(amount, 'ether')
            console.log("----", amt)
            var rawTx = {
                from: fromAddress,
                gasLimit: web3.utils.toHex(2000000),
                to: toAddress,
                value: web3.utils.toHex(amt)
            }
            var tx = new Tx(rawTx);
            var serializedTx = tx.serialize();
            console.log("------------===>", serializedTx)
            console.log("Transaction")
            const contract1 = new web3.eth.Contract(Simple_Account, fromAddress);
            const data = '0x' + serializedTx.toString('hex');
            console.log("================================", data);
            // transaction 2
            const amt1 = web3.utils.toWei('0.001', 'ether')
            var rawTx = {
                from: fromAddress,
                gasLimit: web3.utils.toHex(2000000),
                to: walletAddress,
                value: web3.utils.toHex(amt1)
            }
            var tx = new Tx(rawTx);
            var serializedTx = tx.serialize();
            const data1 = '0x' + serializedTx.toString('hex');
            console.log("================================", data1);
            const address = [toAddress, walletAddress]
            const amounts = [amt, amt1]
            const datas = [data, data1]
            const execute = await contract1.methods.executeBatch(address, amounts, datas).encodeABI();
            console.log("execute")
            const execute_gas = await contract1.methods.executeBatch(address, amounts, datas).estimateGas({ from: walletAddress })
            console.log("executevvvvvv")
            //
            console.log("------------------------->", execute_gas)
            console.log("===========================>", execute)
            // Sign the transaction
            let signedTx = await web3.eth.accounts.signTransaction({

                "to": fromAddress,
                "gas": execute_gas,
                "data": execute,
            }, PVT);
            // const signedTx = await web3.eth.accounts.signTransaction(execute, PVT);
            console.log("=========>", signedTx)
            // Send the transaction
            const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
            console.log("==============>", receipt)
            console.log('Transaction successful with hash:', receipt.transactionHash);
            console.log('Transfer status:', receipt.status ? 'Success' : 'Failure');
            let output = {
                status: 200,
                data: receipt.transactionHash,
            };
            console.log('Resulting:', receipt);
            return output;
        } catch (error) {
            console.log(error);
            if (
                error.message &&
                error.message.includes("insufficient funds for gas")
            ) {
                return {
                    status: 500,
                    error: "Insufficient balance",
                };
            } else {
                return {
                    status: 500,
                    // error: error.message ? error.message : error,
                    error: "Something went wrong. Try again later.",
                };
            }
        }
    },
    sendNFT: async (fromAddress, toAddress, tokenId, token_contract_address, walletAddress) => {
        try {

            const contract = new web3.eth.Contract(ERC721, token_contract_address);
            const txData = await contract.methods.transferFrom(fromAddress, toAddress, tokenId).encodeABI();

            console.log("=============================>", txData);

            const tx = {
                to: toAddress,
                data: txData,
                // gas: await txData1.estimateGas({ from: fromAddress }),
                gas: 2000000

            };

            console.log("----", tx)
            console.log("Transaction")

            const contract1 = new web3.eth.Contract(Simple_Account, fromAddress);
            console.log("contract1===========>",)
            const q = await contract1.methods.owner().call()
            console.log("q===========>", q, walletAddress)
            const data = txData.toString();
            console.log("data===========>", data)
            console.log("fromAddress===========>", fromAddress)


            // transaction 2


            const amt1 = web3.utils.toWei('0.001', 'ether')




            var rawTx = {
                from: fromAddress,
                gas: web3.utils.toHex(2000000),
                to: walletAddress,
                value: web3.utils.toHex(amt1)
            }

            var tx1 = new Tx(rawTx);
            var serializedTx = tx1.serialize();





            const data1 = '0x' + serializedTx.toString('hex');

            console.log("================================", data1);
            const address = [token_contract_address, walletAddress]
            const amounts = [0, amt1]
            const datas = [data, data1]
            const execute = await contract1.methods.executeBatch(address, amounts, datas).encodeABI();
            console.log("execute")



            const execute_gas = await contract1.methods.executeBatch(address, amounts, datas).estimateGas({ from: walletAddress })
            console.log("executevvvvvv")
            //
            console.log("------------------------->", execute_gas)
            console.log("===========================>", execute)
            // Sign the transaction
            let signedTx = await web3.eth.accounts.signTransaction({

                "to": fromAddress,
                "gas": execute_gas,
                "data": execute,
            }, PVT);

            // const signedTx = await web3.eth.accounts.signTransaction(execute, PVT);
            console.log("=========>", signedTx)

            // Send the transaction
            const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
            console.log("==============>", receipt)

            console.log('Transaction successful with hash:', receipt.transactionHash);
            console.log('Transfer status:', receipt.status ? 'Success' : 'Failure');
            let output = {
                status: 200,
                data: receipt.transactionHash,
            };
            console.log('Resulting:', receipt);
            return output;
        } catch (error) {
            console.log(error);
            if (
                error.message &&
                error.message.includes("insufficient funds for gas")
            ) {
                return {
                    status: 500,
                    error: "Insufficient balance",
                };
            } else {
                return {
                    status: 500,
                    // error: error.message ? error.message : error,
                    error: "Something went wrong. Try again later.",
                };
            }
        }
    },


}
module.exports = MainService;
