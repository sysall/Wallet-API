const coin = require("../models/coins");

const seedcoin = async () => {
    let check_item = [
        { name: "Polygon", asset: 'MATIC', contractAddress: '', type: "COIN", network: "MATIC", decimals: 18, },
    ];

    for (let val of check_item) {
        // Check if the asset already exists in the database
        let check_ex = await coin.findOne({ asset: val.asset });

        // If the asset does not exist, save it
        if (!check_ex) {
            await new coin(val).save();
        }
    }

    return true;
};

module.exports = {
    seedcoin
};
