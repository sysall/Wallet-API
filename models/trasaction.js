const mongoose = require('mongoose');

var TransactionSchema = mongoose.Schema({

    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    from: {
        type: String,
    },
    to: {
        type: String,
    },
    tokenid: {
        type: String,
    },
    amount: {
        type: String,
    },
    trasactionHash: {
        type: String,
    },

}, { timestamps: true });

var transaction = mongoose.model('transaction', TransactionSchema);

module.exports = transaction;