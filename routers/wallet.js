const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth");
const asyncHandler = require("../middleware/async");
const WalletController = require("../controllers/wallet");
const walletController = new WalletController();

// user API routes
router.get("/user/get_balance", auth, asyncHandler(walletController.get_Balance));
router.post("/user/create_Wallet", auth, asyncHandler(walletController.create_Wallet));
router.post("/user/import_Token", auth, asyncHandler(walletController.import_Token));

router.post("/user/deposit", auth, asyncHandler(walletController.deposit));
router.post("/user/send", auth, asyncHandler(walletController.send));
router.post("/user/send_Matic", auth, asyncHandler(walletController.send_Matic));
router.post("/user/wallet_recovery", auth, asyncHandler(walletController.deposit));
router.post("/user/Transaction_history", auth, asyncHandler(walletController.Transaction_history));
router.post("/user/sendNFT", auth, asyncHandler(walletController.sendNft));




module.exports = router;

