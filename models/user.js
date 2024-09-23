const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// PassWord Validation
var validatePassword = function (password) {
    //var strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/;
    var strongRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#()+-_\$%\^&\*])(?=.{8,})/;
    return strongRegex.test(password);
};
const UserScheme = new mongoose.Schema(
    {
        walletAddress: {
            type: String,
            lowercase: true,
        },
        email: {
            type: String,
            unique: true,
        },
        smartWallet: {
            type: String,
            lowercase: true,
        },

        role: {
            type: String,
            default: "USER",
            enum: ["USER", "ADMIN"],
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
        isApproved: {
            type: Boolean,
            default: false
        },
        Action: {
            type: Boolean,
            default: true,
        },
        status: {
            type: Boolean,
            default: true,
        },
        notes: {
            type: String,
            enum: ["LOGGED_IN", "LOGGED_OUT"],
        },
        salt: {
            type: String,
        },
        ip_address: {
            type: String,
        },

        password: {
            type: String,
            trim: true,
            minlength: 8,
            required: [false, "please provide password min 8 char"],
            validate: [
                validatePassword,
                "Password Invalid format. At least 1 capital letter.., 1 lowercase letter.., 1 special character.., 1 numeric character..,",
            ],
            select: false
        },

        confirmPassword: { type: String },
        country: {
            type: String,
        },
        country_code: {
            type: String,
        },
    },
    { timestamps: true }
);

// Sign JWT and return
UserScheme.methods.generateAuthToken = async function () {
    const user = this;
    const token = await jwt.sign(
        { _id: user._id.toString() },
        process.env.JWT_SECRET,
        {
            expiresIn: process.env.JWT_EXPIRE,
        }
    );
    return token;
};

const User = mongoose.model("User", UserScheme);

module.exports = User;
