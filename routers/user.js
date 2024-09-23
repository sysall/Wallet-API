const express = require("express");
const auth = require("../middleware/auth");
const asyncHandler = require("../middleware/async");
const UserController = require("../controllers/user");
const usercontroller = new UserController();

const router = express.Router();

// User Api's
router.post("/user/login", asyncHandler(usercontroller.login));
router.post("/user/register ", asyncHandler(usercontroller.login));

module.exports = router;
