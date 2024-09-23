const mongoose = require('mongoose');

var CoinSchema = mongoose.Schema({

    asset: {
        type: String,
    },
    walletAddress: {
        type: String,
    },

    contractAddress: {
        type: String,
    },
    type: {
        type: String,
    },
    network: {
        type: String,
    },
    name: {
        type: String,
    },
    decimals: {
        type: Number,
    }
}, { timestamps: true });

var coin = mongoose.model('coins', CoinSchema);

module.exports = coin;