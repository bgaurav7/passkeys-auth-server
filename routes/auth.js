var express = require("express");
const AuthController = require("../controllers/AuthController");

var router = express.Router();

router.post("/register-password", AuthController.registerPassword);
router.post("/login-password", AuthController.loginPassword);
router.post("/verify-otp", AuthController.verifyConfirm);
router.post("/resend-verify-otp", AuthController.resendConfirmOtp);

module.exports = router;