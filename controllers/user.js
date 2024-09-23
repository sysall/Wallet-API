const ErrorResponse = require("../utils/errorResponse");
const asyncHandler = require("../middleware/async");
const cryptoEncrypt = require("../utils/crypto");
const bcrypt = require('bcryptjs');
const User = require("../models/user");
const contract_Service = require("../services/account_abstraction")
const Web3 = require("web3");
const ownerAddress = process.env.OWNER_ADDRESS
class UserController {
    constructor() { }

    async encryptData(req, res) {
        let data = {};
        for (let key in req.body) {
            let encrypted = cryptoEncrypt.encrypt(req.body[key]);
            console.log(key, ":", encrypted);
            data[key] = encrypted;
        }
        res.status(200).json({ success: true, message: "Encrypted", data: data });
    }


    async login(req, res) {
        try {
            const { email, password, confirmPassword } = req.body;
            const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

            // Check if email is provided (First-time login)
            if (email) {
                // Email validation
                if (!email) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Please Provide Email Address",
                    });
                }

                if (email === null) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Email cannot be null",
                    });
                }

                // Simple email format validation (You might want to use a more robust regex or a library like validator.js)
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Please Provide a Valid Email Address",
                    });
                }
                // Password format validation
                const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

                if (!passwordRegex.test(password)) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Password Invalid format. At least 1 capital letter, 1 lowercase letter, 1 special character, 1 numeric character.",
                    });
                }

                if (password.length < 8) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Please provide a password with a minimum of 8 characters",
                    });
                }


                // Handle first-time user registration
                if (!confirmPassword) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Please Provide Confirm Password",
                    });
                }

                if (password !== confirmPassword) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Passwords do not match",
                    });
                }

                // Check if email already exists
                const existingUser = await User.findOne({ email });

                if (existingUser) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "Email address already exists. Please use a different email.",
                    });
                }

                // Hash the password
                const hashedPassword = await bcrypt.hash(password, 10);

                const newUser = new User({
                    email,
                    password: hashedPassword, // Save hashed password
                    signature: req.body.signature,
                    isVerified: true,
                    notes: "LOGGED_IN",
                    status: true,
                    Action: true, // Assuming new users should have action set to true
                    ip_address: ipAddress, // Store IP address
                });

                const output = {
                    email,
                    signature: req.body.signature,
                    isVerified: true,
                    notes: "LOGGED_IN",
                    status: true,
                    Action: true, // Assuming new users should have action set to true
                    ip_address: ipAddress, // Store IP address
                };


                await newUser.save();

                const token = await newUser.generateAuthToken();
                return res
                    .cookie("token", token, {
                        maxAge: 1000 * 60 * 60 * 24,
                        httpOnly: false,
                    })
                    .json({
                        status: 200,
                        success: true,
                        data: output,
                        message: "Registration Successful and Logged in",
                    });

            } else {
                const salt = req.body.salt;

                // Check if the provided salt is already used by any other user
                const existingUserWithSalt = await User.findOne({ salt });

                if (existingUserWithSalt && existingUserWithSalt.ip_address !== ipAddress) {
                    return res.status(400).json({
                        status: 400,
                        success: false,
                        message: "This salt is used by another user",
                    });
                }

                // Find the user by IP address and include password field
                const existingUser = await User.findOne({ ip_address: ipAddress }).select('+password');

                if (!existingUser) {
                    return res.status(404).json({
                        status: 404,
                        success: false,
                        message: "User not found with this IP address",
                    });
                }

                // Check if the user has a salt field
                if (!existingUser.salt) {
                    // Add the salt field and save the user
                    existingUser.salt = salt;
                    await existingUser.save();
                } else {
                    // Compare the existing salt with the provided salt
                    if (existingUser.salt !== salt) {
                        return res.status(400).json({
                            status: 400,
                            success: false,
                            message: "Salt does not match",
                        });
                    }
                }

                // Check if the provided password matches the stored password
                const isMatch = await bcrypt.compare(req.body.password, existingUser.password);

                if (!isMatch) {
                    return res.status(401).json({
                        status: 401,
                        success: false,
                        message: "Invalid Password",
                    });
                }

                // Add the functionality to check and create a smart wallet if necessary
                if (!existingUser.smartWallet) {
                    let createAccount = await contract_Service.createAccount(ownerAddress, salt);

                    if (createAccount && createAccount.status == 200) {
                        existingUser.smartWallet = createAccount.data;
                        existingUser.salt = req.body.salt;
                        await existingUser.save();
                        const output = {
                            ip_address: existingUser.ip_address,
                            notes: "LOGGED_IN",
                            smartAddress: existingUser.smartWallet
                        }

                        return res.json({
                            status: 200,
                            success: true,
                            message: "Wallet created successfully.",
                            data: output
                        });
                    } else {
                        return res.status(500).json({
                            status: 500,
                            success: false,
                            message: "Failed to create wallet.",
                        });
                    }
                } else {
                    // If smartWallet exists, proceed with login
                    if (existingUser.status) {
                        if (existingUser.Action) {
                            existingUser.signature = req.body.signature;
                            existingUser.notes = "LOGGED_IN";
                            await existingUser.save();

                            const output = {
                                ip_address: existingUser.ip_address,
                                notes: "LOGGED_IN",
                                smartAddress: existingUser.smartWallet
                            }

                            const token = await existingUser.generateAuthToken();
                            return res
                                .cookie("token", token, {
                                    maxAge: 1000 * 60 * 60 * 24,
                                    httpOnly: false,
                                })
                                .json({
                                    status: 200,
                                    success: true,
                                    data: output,
                                    message: "Logged in Successfully",
                                });
                        } else {
                            return res.status(403).json({
                                status: 403,
                                success: false,
                                message: "You are restricted by the admin",
                            });
                        }
                    } else {
                        return res.status(400).json({
                            status: 400,
                            success: false,
                            message: "Sorry Your Account is Inactive Please Contact Admin",
                        });
                    }
                }
            }




        } catch (error) {
            // Handle MongoDB duplicate key error
            if (error.code === 11000 && error.keyPattern.email) {
                return res.status(400).json({
                    status: 400,
                    success: false,
                    message: "Email address already exists. Please use a different email.",
                });
            }

            console.log("Error @ login : ", error);
            return res.status(500).json({
                status: 500,
                success: false,
                message: "Failed in Signin",
                error: error,
            });
        }
    }

}

module.exports = UserController;
