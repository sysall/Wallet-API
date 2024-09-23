const Users = require("../models/user")
const Coins = require("../models/coins")
const Transaction = require("../models/trasaction")
const contract_Service = require("../services/account_abstraction")
const Web3 = require("web3");
const main_ownerAddress = process.env.OWNER_ADDRESS

class WalletController {
    constructor() { }


    async create_Wallet(req, res) {
        try {
            let user = req.user;

            const ownerAddress = main_ownerAddress
            const salt = req.body.salt

            let createAccount = await contract_Service.createAccount(ownerAddress, salt);

            if (createAccount && createAccount.status == 200) {

                const User = await Users.findById(user.id);
                User.smartWallet = createAccount.data;
                User.salt = req.body.salt;

                await User.save();
                return res.json({ status: 200, success: true, message: " Wallet created Successfully. ", data: User });
            }

        } catch (error) {
            console.log("Error @ create_Wallet : ", error);
            return res.status(500).json({ status: 500, success: false, message: error.message ? error.message : " Error ocurred !! " });
        }
    }


    async import_Token(req, res) {
        try {
            let user = req.user;

            // Check if any required field is empty
            const { asset, contractAddress, type, name, network, decimals } = req.body;
            if (!asset || !contractAddress || !type || !name || !network || !decimals) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "All fields are required and must not be empty.",
                });
            }


            // Check if the token already exists in the database
            let existingToken = await Coins.findOne({
                asset: req.body.asset,
                walletAddress: user.walletAddress,
                contractAddress: req.body.contractAddress,
                type: req.body.type,
                name: req.body.name,
                network: req.body.network,
                decimals: req.body.decimals,
            });

            // If the token already exists, return a message
            if (existingToken) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Token already imported.",
                });
            }

            // If the token does not exist, save it
            let CoinsList = await new Coins({
                asset: req.body.asset,
                walletAddress: user.walletAddress,
                contractAddress: req.body.contractAddress,
                type: req.body.type,
                name: req.body.name,
                network: req.body.network,
                decimals: req.body.decimals,
            }).save();

            return res.json({ status: 200, success: true, message: "Token Imported Successfully. ", data: CoinsList });
        } catch (error) {
            console.log("Error @ import_Token : ", error);
            return res.status(500).json({ status: 500, success: false, message: error.message ? error.message : " Error ocurred !! " });
        }
    }


    async get_Balance(req, res) {
        try {
            let user = req.user;
            let listBalance = [];
            let userWalletAddress = user.smartWallet;
            console.log("============?", user.smartWallet)
            // Query to find all documents where walletAddress is either equal to user's walletAddress or null
            let coins = await Coins.find({
                $or: [
                    { walletAddress: userWalletAddress },
                    { walletAddress: null }
                ]
            });

            for (let asset of coins) {
                let balanceData = {
                    asset: asset.asset,
                    contractAddress: asset.contractAddress,
                    type: asset.type,
                    network: asset.network,
                    balance: 0,
                    worth: 0
                };
                if (asset.network) {
                    let response;
                    switch (asset.network) {

                        case 'MATIC':
                            response = await contract_Service.getBalance(user.smartWallet, asset);
                            break;
                        default:
                            break;
                    }

                    if (response && response.status === 200) {
                        console.log(response)
                        balanceData.balance = +response.data.balance;
                        balanceData.worth = +(+response.data.balance);
                    }
                }
                listBalance.push(balanceData);

            }

            return res.json({ status: 200, success: true, message: " Balance Details Fetched. ", data: listBalance, });
        } catch (error) {
            console.log("Error @ get_Balance : ", error);
            return res.status(500).json({ status: 500, success: false, message: error.message ? error.message : " Error ocurred !! " });
        }
    }

    async send(req, res) {
        try {
            let user = req.user;
            const walletAddress = main_ownerAddress
            const fromAddress = req.user.smartWallet
            const toAddress = req.body.toAddress
            const token_contract_address = req.body.token_contract_address
            const amount = req.body.amount
            if (!req.body.toAddress) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Please Provide Reciver address",
                });
            }

            if (!req.body.toAddress) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Please Provide Reciver address",
                });
            }
            let address = Web3.utils.isAddress(req.body.toAddress)
            if (address == false) {
                console.log("Please enter")
                return res.status(400).send({ status: 400, success: false, message: "Address Invalid, Check the Wallet Address" })
            }
            if (!req.body.amount) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Please Provide amount As Number",
                });
            }

            if (isNaN(amount)) {
                return res.status(400).json({ status: 400, success: false, message: "amount must be a number." });
            }

            let createAccount = await contract_Service.sendAmount(fromAddress, toAddress, amount, token_contract_address, walletAddress);

            if (createAccount && createAccount.status == 200) {
                const hash = createAccount.toString();
                let TrasactionList = await new Transaction({
                    from: fromAddress,
                    to: toAddress,
                    amount: amount,
                    trasactionHash: createAccount.data,
                }).save();

                return res.json({ status: 200, success: true, message: "Transaction Successfull. ", data: TrasactionList });
            }
            else {
                if (createAccount.error === "Insufficient balance") {
                    console.log("=====================>", createAccount.error)
                    return res.status(400).json({ message: "Insufficient  balance", success: false });
                }
                return res.status(400).json({ message: createAccount.error, success: false });

            }

        } catch (error) {
            console.log("Error @ send : ", error)
            return res.status(500).json({ success: false, data: error, message: "Request Failed" })
        }
    }

    async send_Matic(req, res) {
        try {
            let user = req.user;
            const walletAddress = main_ownerAddress
            const fromAddress = req.user.smartWallet
            const toAddress = req.body.toAddress
            const amount = req.body.amount
            const token_contract_address = req.body.token_contract_address
            let createAccount = await contract_Service.sendMatic(fromAddress, toAddress, amount, walletAddress);

            if (!req.body.toAddress) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Please Provide Reciver address",
                });
            }

            let address = Web3.utils.isAddress(req.body.toAddress)
            if (address == false) {
                console.log("Please enter")
                return res.status(400).send({ status: 400, success: false, message: "Address Invalid, Check the Wallet Address" })
            }
            if (!req.body.amount) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Please Provide amount As Number",
                });
            }

            if (isNaN(amount)) {
                return res.status(400).json({ status: 400, success: false, message: "Salt must be a number." });
            }

            if (createAccount && createAccount.status == 200) {
                const hash = createAccount.toString();
                let TrasactionList = await new Transaction({
                    user_id: req.user._id,
                    from: fromAddress,
                    to: toAddress,
                    amount: amount,
                    trasactionHash: createAccount.data,
                }).save();

                return res.json({ status: 200, success: true, message: "Transaction Successfull. ", data: TrasactionList });
            } else {
                if (createAccount.error === "Insufficient balance") {
                    console.log("=====================>", createAccount.error)
                    return res.status(400).json({ message: "Insufficient  balance", success: false });
                }
                return res.status(400).json({ message: createAccount.error, success: false });

            }

        } catch (error) {
            console.log("Error @ send : ", error)
            return res.status(500).json({ success: false, data: error, message: "Request Failed" })
        }
    }


    async sendNft(req, res) {
        try {
            let user = req.user;
            const walletAddress = main_ownerAddress
            const fromAddress = req.user.smartWallet
            const toAddress = req.body.toAddress
            const tokenId = req.body.tokenId
            const token_contract_address = req.body.token_contract_address
            let createAccount = await contract_Service.sendNFT(fromAddress, toAddress, tokenId, token_contract_address, walletAddress);

            if (createAccount && createAccount.status == 200) {
                const hash = createAccount.toString();
                let TrasactionList = await new Transaction({
                    user_id: req.user._id,
                    from: fromAddress,
                    to: toAddress,
                    tokenID: tokenId,
                    trasactionHash: createAccount.data,
                }).save();

                return res.json({ status: 200, success: true, message: "Transaction Successfull. ", data: TrasactionList });
            }
            else {
                if (createAccount.error === "Insufficient balance") {
                    console.log("=====================>", createAccount.error)
                    return res.status(400).json({ message: "Insufficient  balance", success: false });
                }
                return res.status(400).json({ message: createAccount.error, success: false });

            }

        } catch (error) {
            console.log("Error @ send : ", error)
            return res.status(500).json({ success: false, data: error, message: "Request Failed" })
        }
    }

    async deposit(req, res) {
        try {
            let user = req.user.salt;

            const ownerAddress = process.env.OWNER_ADDRESS
            const salt = req.body.salt
            // Check if the user's salt matches the salt in the request body
            if (req.user.salt !== req.body.salt) {
                return res.status(400).json({ status: 400, success: false, message: "Invalid salt" });
            }
            let createAccount = await contract_Service.deposit(ownerAddress, salt);

            if (createAccount && createAccount.status == 200) {

                return res.json({ status: 200, success: true, message: "Address fetched. ", data: createAccount });
            }

        } catch (error) {
            console.log("Error @ deposit : ", error);
            return res.status(500).json({ status: 500, success: false, message: error.message ? error.message : " Error ocurred !! " });
        }
    }

    async Transaction_history(req, res) {
        try {
            let user = req.user;
            console.log("Transaction", user._id)
            let page = req.body.pages || 1;
            let limit = req.body.limit || 10;
            let skip = (page - 1) * limit;

            // Search for transactions where the 'from' or 'to' field matches the user's smartWallet
            let search = { user_id: user._id };

            let TransactionHistorys = await Transaction.find(search)
                .skip(skip)
                .limit(limit)
                .sort({ _id: -1 });

            let count = await Transaction.countDocuments(search);

            return res.status(200).send({
                status: 200,
                success: true,
                message: "Successfully fetched Transaction History.",
                data: TransactionHistorys,
                count: count,
            });

        } catch (error) {
            console.log("Error @ deposit: ", error);
            return res.status(500).json({
                status: 500,
                success: false,
                message: error.message ? error.message : "An error occurred!"
            });
        }
    }


}
module.exports = WalletController;



// async account_Details(req, res) {
//     try {
//         let user = req.user;


//         return res.json({ status: 200, success: true, message: "Account Details Fetched. ", data: user });
//     } catch (error) {
//         console.log("Error @ account_Details : ", error);
//         return res.status(500).json({ status: 500, success: false, message: error.message ? error.message : " Error ocurred !! " });
//     }
// }
