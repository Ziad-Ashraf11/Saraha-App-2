import { BadRequestException } from "../../Utils/Response/error.response.js";

export const validateRegister = (req, res, next) => {
	const { firstName, lastName, email, password } = req.body ?? {};
	if (![firstName, lastName, email, password].every((value) => typeof value === "string" && value.trim())) {
		throw BadRequestException({ Message: "firstName, lastName, email, and password are required" });
	}
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
		throw BadRequestException({ Message: "A valid email is required" });
	}
	if (password.length < 8 || password.length > 72) {
		throw BadRequestException({ Message: "Password must be between 8 and 72 characters" });
	}
	next();
};

export const validateLogin = (req, res, next) => {
	const { email, password } = req.body ?? {};
	if (![email, password].every((value) => typeof value === "string" && value.trim())) {
		throw BadRequestException({ Message: "Email and password are required" });
	}
	next();
};

export const validateEmailVerification = (req, res, next) => {
	const { email, code } = req.body ?? {};
	if (typeof email !== "string" || typeof code !== "string" || !/^\d{6}$/.test(code)) {
		throw BadRequestException({ Message: "A valid email and six-digit code are required" });
	}
	next();
};

export const validateResendVerification = (req, res, next) => {
	if (typeof req.body?.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.email.trim())) {
		throw BadRequestException({ Message: "A valid email is required" });
	}
	next();
};

export const validateRefreshToken = (req, res, next) => {
	if (typeof req.body?.refreshToken !== "string" || !req.body.refreshToken.trim()) {
		throw BadRequestException({ Message: "refreshToken is required" });
	}
	next();
};

export const validateGoogleLogin = (req, res, next) => {
	if (typeof req.body?.idToken !== "string" || !req.body.idToken.trim()) {
		throw BadRequestException({ Message: "Google idToken is required" });
	}
	next();
};

export const validateForgotPassword = (req, res, next) => {
	if (typeof req.body?.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.email.trim())) {
		throw BadRequestException({ Message: "A valid email is required" });
	}
	next();
};

export const validateResetPassword = (req, res, next) => {
	const { token, password } = req.body ?? {};
	if (typeof token !== "string" || token.length < 32) {
		throw BadRequestException({ Message: "A valid password reset token is required" });
	}
	if (typeof password !== "string" || password.length < 8 || password.length > 72) {
		throw BadRequestException({ Message: "Password must be between 8 and 72 characters" });
	}
	next();
};
