var express = require("express");
const AuthPasskeysController = require("../controllers/AuthPasskeysController");
const AuthPasswordController = require("../controllers/AuthPasswordController");

var router = express.Router();

router.post("/register-password", AuthPasswordController.registerPassword);
router.post("/register-verify-password", AuthPasswordController.registerVerifyPassword);
// router.post("/resend-verify-otp", AuthPasswordController.resendConfirmOtp);
router.post("/login-password", AuthPasswordController.loginPassword);

router.post("/register-passkeys", AuthPasskeysController.registerPasskeys);
router.post("/register-verify-passkeys", AuthPasskeysController.registerVerifyPasskeys);
router.post("/login-passkeys", AuthPasskeysController.loginPasskeys);
router.post("/login-verify-passkeys", AuthPasskeysController.loginVerifyPasskeys);

module.exports = router;