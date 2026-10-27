import {Router} from "express";
import successResponse from "../../Utils/Response/success.response.js";
import { confirmTwoFactorEnable, confirmTwoFactorLogin, enableTwoFactor, forgotPassword, googleLogin, login, logout, refreshTokens, register, resendVerificationEmail, resetPassword, verifyEmail } from "./auth.service.js";
import { authenticate } from "../../middleware/auth.middleware.js";
import {
	validateEmailVerification,
	validateForgotPassword,
	validateGoogleLogin,
	validateLogin,
	validateRefreshToken,
	validateRegister,
	validateResendVerification,
	validateResetPassword,
	validateTwoFactorCode,
	validateTwoFactorLogin,
} from "./auth.validiation.js";

const router = Router();

router.post("/register", validateRegister, async (req, res) => {
	const result = await register(req.body);
	return successResponse(res, 201, "Account created", result);
});

router.post("/login", validateLogin, async (req, res) => {
	const result = await login(req.body);
	return successResponse(res, 200, result.twoFactorVerificationRequired ? "Two-step verification code sent" : "Login successful", result);
});

router.post("/2fa/enable", authenticate, async (req, res) => {
	return successResponse(res, 200, "Two-step verification code sent", await enableTwoFactor(req.user._id));
});

router.post("/2fa/enable/confirm", authenticate, validateTwoFactorCode, async (req, res) => {
	return successResponse(res, 200, "Two-step verification enabled", await confirmTwoFactorEnable(req.user._id, req.body.code));
});

router.post("/2fa/login/confirm", validateTwoFactorLogin, async (req, res) => {
	return successResponse(res, 200, "Login successful", await confirmTwoFactorLogin(req.body));
});

router.post("/verify-email", validateEmailVerification, async (req, res) => {
	return successResponse(res, 200, "Email verified", await verifyEmail(req.body));
});

router.post("/resend-verification", validateResendVerification, async (req, res) => {
	return successResponse(res, 200, "If the account needs verification, a code has been sent", await resendVerificationEmail(req.body.email));
});

router.post("/forgot-password", validateForgotPassword, async (req, res) => {
	return successResponse(res, 200, "If the account exists, password reset instructions have been sent", await forgotPassword(req.body.email));
});

router.post("/reset-password", validateResetPassword, async (req, res) => {
	return successResponse(res, 200, "Password reset successful", await resetPassword(req.body));
});

router.post("/revoke-token", validateRefreshToken, async (req, res) => {
	const result = await refreshTokens(req.body.refreshToken);
	await logout(result.user._id);
	return successResponse(res, 200, "Token revoked", { revoked: true });
});

router.post("/refresh", validateRefreshToken, async (req, res) => {
	return successResponse(res, 200, "Tokens refreshed", await refreshTokens(req.body.refreshToken));
});

router.post("/google", validateGoogleLogin, async (req, res) => {
	return successResponse(res, 200, "Google login successful", await googleLogin(req.body.idToken));
});

router.post("/logout", authenticate, async (req, res) => {
	return successResponse(res, 200, "Logged out", await logout(req.user._id));
});

export default router;
