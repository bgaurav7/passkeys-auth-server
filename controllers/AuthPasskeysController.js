const UserModel = require("../models/UserModel");
const { body,validationResult } = require("express-validator");
const SimpleWebAuthnServer = require('@simplewebauthn/server');
//helper file to prepare responses.
const apiResponse = require("../helpers/apiResponse");
const utility = require("../helpers/utility");
const passkeys = require("../helpers/passkeys");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mailer = require("../helpers/mailer");
const { constants } = require("../helpers/constants");

/**
 * User registration via passkey
 *
 * @param {string}      firstName
 * @param {string}      lastName
 * @param {string}      email
 *
 * @returns {Object}
 */
exports.registerPasskeys = [
	// Validate fields.
	body("firstName").isLength({ min: 1 }).trim().withMessage("First name must be specified.")
		.isAlphanumeric().withMessage("First name has non-alphanumeric characters.").escape(),
	body("lastName").isLength({ min: 1 }).trim().withMessage("Last name must be specified.")
		.isAlphanumeric().withMessage("Last name has non-alphanumeric characters.").escape(),
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").custom((value) => {
			return UserModel.findOne({email : value}).then((user) => {
				if (user && user.isConfirmed) {
					return Promise.reject("Account already registered.");
				}
			});
		}).escape(),
	// Process request after validation and sanitization.
	(req, res) => {
		try {
			// Extract the validation errors from a request.
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				// Display sanitized values/errors messages.
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				const password = utility.randomPassword()
				const challenge = passkeys.convertChallenge(passkeys.getNewChallenge())
				console.log("registerPasskeys challenge=", challenge);
				//hash generated password
				bcrypt.hash(password,10,function(err, hash) {
					// generate OTP for confirmation
					let otp = utility.randomNumber(4);
					// Create User object with escaped and trimmed data
					var user = new UserModel(
						{
							firstName: req.body.firstName,
							lastName: req.body.lastName,
							email: req.body.email,
							password: hash,
							confirmOTP: otp,
							challenge: challenge
						}
					);
					// Html email body
					let html = "<p>Please Confirm your Account.</p><p>OTP: "+otp+"</p>";
					// Send confirmation email
					mailer.send(
						constants.confirmEmails.from, 
						req.body.email,
						"Confirm Account",
						html
					).then(function(){
						// Save user.
						user.save(function (err) {
							if (err) { return apiResponse.ErrorResponse(res, err); }
							let userData = {
								_id: user._id,
								firstName: user.firstName,
								lastName: user.lastName,
								email: user.email
							};

							console.log("registerPasskeys savedChallenge=", user.challenge);

							// ID isn't visible by users, but needs to be random enough and valid base64 (for Android)
							const userId = user._id.toString("base64")
							console.log("registerPasskeys userId=", userId);

							//Configure Passkeys Challenge Request
							// TODO: Move to Central Config
							const requestData = {
								challenge: challenge,
								rp: {
									id: passkeys.getRpId(), 
									name: 'webauthn-app'
								},
								user: {
									id: userId, 
									name: user.firstName, 
									displayName: user.fullName
								},
								pubKeyCredParams: [
									{type: 'public-key', alg: -7},
									{type: 'public-key', alg: -257},
								],
								authenticatorSelection: {
									authenticatorAttachment: 'platform',
									userVerification: 'required',
									residentKey: 'preferred',
									requireResidentKey: false,
								}
							};

							return apiResponse.successResponseWithDataWithReq(res,"Registration Success.", userData, requestData);
						});
					}).catch(err => {
						console.log(err);
						return apiResponse.ErrorResponse(res,err);
					});
				});
			}
		} catch (err) {
			console.log(err)
			//throw error in json response with status 500.
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * Verify Confirm otp with Passkeys.
 *
 * @param {string}      email
 * @param {string}      otp
 * @param {string}      response
 *
 * @returns {Object}
 */
exports.registerVerifyPasskeys = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").escape(),
	body("otp").isLength({ min: 1 }).trim().withMessage("OTP must be specified.").escape(),
	body("response").isLength({ min: 2 }).trim().withMessage("Passkeys Request must be specified."),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				var query = {email : req.body.email};
				UserModel.findOne(query).then(async user => {
					if (user) {
						//Check already confirm or not.
						if(!user.isConfirmed) {
							let verification;
							try {
								let responseJson = JSON.parse(req.body.response);
								// console.log("verifyPasskeys responseJson=", responseJson);
								// console.log("verifyPasskeys challenge=", user.challenge);
								verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
									response: responseJson,
									expectedChallenge: user.challenge,
									expectedOrigin: passkeys.expectedOrigins()
								});
							} catch (error) {
								console.error(error);
								return apiResponse.unauthorizedResponse(res, "Passkey verification failed");
							}
							const {verified, registrationInfo} = verification;
							console.log("verifyPasskeys verification=", verified, registrationInfo);
							//Check account confirmation.
							if(verified && user.confirmOTP == req.body.otp){
								//Update user as confirmed
								UserModel.findOneAndUpdate(query, {
									isConfirmed: 1,
									confirmOTP: null,
									registrationInfo: JSON.stringify(registrationInfo, utility.jsonReplacer),
								}).catch(err => {
									console.log(err)
									return apiResponse.ErrorResponse(res, err);
								});
								return apiResponse.successResponse(res,"Account confirmed success.");
							} else {
								return apiResponse.unauthorizedResponse(res, "Otp does not match");
							}
						} else {
							return apiResponse.unauthorizedResponse(res, "Account already confirmed.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Specified email not found.");
					}
				});
			}
		} catch (err) {
			console.error(err);
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * User login passkeys.
 *
 * @param {string}      email
 * 
 *
 * @returns {Object}
 */
exports.loginPasskeys = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				UserModel.findOne({email : req.body.email}).then(user => {
					if (user) {
						//Check account confirmation.
						if(user.isConfirmed && user.registrationInfo != undefined){
							// Check User's account active or not.
							if(user.status) {
								const challenge = passkeys.convertChallenge(passkeys.getNewChallenge())
								console.log("loginPasskeys challenge=", challenge);
								user.challenge = challenge
								user.save(function (err) {
									if (err) { return apiResponse.ErrorResponse(res, err); }

									let userData = {
										_id: user._id,
										email: user.email,
									};

									
									const rpId = passkeys.getRpId()
									console.log("loginPasskeys rpId=", rpId);
									let registrationInfo = JSON.parse(user.registrationInfo, utility.jsonReviver);
									console.log("loginPasskeys credentialID=", registrationInfo.credentialID);
									let responseJson = {
										challenge,
										rpId,
										allowCredentials: [{
											type: 'public-key',
											id: registrationInfo.credentialID,
											transports: ['internal'],
										}],
										userVerification: 'preferred',
									}
									return apiResponse.successResponseWithDataWithReq(res,"Login Start Success.", userData, responseJson);
								});
							} else {
								return apiResponse.unauthorizedResponse(res, "Account is not active. Please contact admin.");
							}
						} else {
							return apiResponse.unauthorizedResponse(res, "Account is not confirmed. Please confirm your account.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
					}
				});
			}
		} catch (err) {
			console.log(err)
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * User login verify passkeys
 *
 * @param {string}      email
 * @param {string}      response
 *
 * @returns {Object}
 */
exports.loginVerifyPasskeys = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").escape(),
	body("response").isLength({ min: 2 }).trim().withMessage("Passkeys response must be specified."),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				console.log("loginVerifyPasskeys email=", req.body.email)
				UserModel.findOne({email : req.body.email}).then(async user => {
					if (user) {
						//Check account confirmation.
						if(user.isConfirmed){
							// Check User's account active or not.
							if(user.status) {
								let verification;
								try {
									const registrationInfo = JSON.parse(user.registrationInfo, utility.jsonReviver)
									console.log("loginVerifyPasskeys registrationInfo=", registrationInfo)
									const rpId = passkeys.getRpId()
									const challenge = user.challenge;
									console.log("loginVerifyPasskeys challenge=", challenge);
									const responseData = JSON.parse(req.body.response);
									console.log("loginVerifyPasskeys responseJson=", responseData);
									const expectedOrigin = passkeys.expectedOrigins()
									verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
										expectedChallenge: challenge,
										response: responseData,
										authenticator: registrationInfo,
										expectedRPID: rpId,
										expectedOrigin,
										requireUserVerification: false
									});
								} catch (error) {
									console.error(error);
									return apiResponse.unauthorizedResponse(res, "Account verififcation failed.");
								}
								const {verified} = verification;

								if(verified) {
									let userData = {
										_id: user._id,
										firstName: user.firstName,
										lastName: user.lastName,
										email: user.email,
									};
									//Prepare JWT token for authentication
									const jwtPayload = userData;
									const jwtData = {
										expiresIn: process.env.JWT_TIMEOUT_DURATION,
									};
									const secret = process.env.JWT_SECRET;
									//Generated JWT token with Payload and secret.
									userData.token = jwt.sign(jwtPayload, secret, jwtData);
									return apiResponse.successResponseWithData(res,"Login Success.", userData);
								} else {
									return apiResponse.unauthorizedResponse(res, "Account verififcation failed.");
								}
							} else {
								return apiResponse.unauthorizedResponse(res, "Account is not active. Please contact admin.");
							}
						} else {
							return apiResponse.unauthorizedResponse(res, "Account is not confirmed. Please confirm your account.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
					}
				});
			}
		} catch (err) {
			console.error(err);
			return apiResponse.ErrorResponse(res, err);
		}
	}];