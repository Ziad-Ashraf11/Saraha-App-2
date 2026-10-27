import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomInt, randomBytes, createHash } from "node:crypto";
import { OAuth2Client } from "google-auth-library";
import UserModel from "../../DB/models/user.model.js";
import { create, findOne, findById, findByIdAndUpdate } from "../../DB/database.repository.js";
import { JWT_SECRET, JWT_REFRESH_SECRET, GOOGLE_CLIENT_ID } from "../../../config/config.service.js";
import { sendPasswordResetEmail, sendVerificationEmail } from "../../Utils/email.util.js";
import { BadRequestException, ConflictException, ForbiddenException, UnauthorizedException } from "../../Utils/Response/error.response.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const createTokenPair = async (user) => {
	if (!JWT_SECRET || !JWT_REFRESH_SECRET) throw new Error("JWT secrets are missing from environment configuration");
	const accessToken = jwt.sign(
		{ sub: user._id.toString(), role: user.role, type: "access", tokenVersion: user.tokenVersion ?? 0 },
		JWT_SECRET,
		{ expiresIn: "15m", issuer: "saraha-api", audience: "saraha-client" },
	);
	const refreshToken = jwt.sign(
		{ sub: user._id.toString(), type: "refresh", tokenVersion: user.tokenVersion ?? 0, nonce: randomBytes(16).toString("hex") },
		JWT_REFRESH_SECRET,
		{ expiresIn: "7d", issuer: "saraha-api", audience: "saraha-client" },
	);
	await findByIdAndUpdate({
		model: UserModel,
		id: user._id,
		update: { $set: { refreshTokenHash: hash(refreshToken) } },
	});
	return { accessToken, refreshToken };
};

export const register = async ({ firstName, lastName, email, password }) => {
	const normalizedEmail = email.trim().toLowerCase();
	if (await findOne({ model: UserModel, filter: { email: normalizedEmail }, select: "_id", options: { lean: true } })) {
		throw ConflictException({ Message: "Email is already registered" });
	}
	const passwordHash = await bcrypt.hash(password, 12);
	const verificationCode = String(randomInt(100000, 1000000));
	const resendAfter = new Date(Date.now() + 60 * 1000);
	const user = await create({
		model: UserModel,
		data: {
			firstName: firstName.trim(),
			lastName: lastName.trim(),
			email: normalizedEmail,
			password: passwordHash,
			emailVerificationCodeHash: hash(verificationCode),
			emailVerificationExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
			emailVerificationResendAt: resendAfter,
		},
	});
	let emailResult;
	try {
		emailResult = await sendVerificationEmail(normalizedEmail, verificationCode);
	} catch (error) {
		await UserModel.deleteOne({ _id: user._id });
		throw error;
	}
	return {
		user,
		emailVerificationRequired: true,
		...(emailResult.developmentCode && { developmentVerificationCode: emailResult.developmentCode }),
	};
};

export const login = async ({ email, password }) => {
	const user = await findOne({
		model: UserModel,
		filter: { email: email.trim().toLowerCase() },
		select: "+password",
	});
	if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
		throw UnauthorizedException({ Message: "Invalid email or password" });
	}
	if (!user.confirmEmail) throw ForbiddenException({ Message: "Verify your email before logging in" });
	const tokens = await createTokenPair(user);
	return { user, ...tokens };
};

export const verifyEmail = async ({ email, code }) => {
	const normalizedEmail = email.trim().toLowerCase();
	const user = await findOne({
		model: UserModel,
		filter: { email: normalizedEmail },
		select: "+emailVerificationCodeHash +emailVerificationExpiresAt",
	});
	if (!user || !user.emailVerificationCodeHash || user.emailVerificationExpiresAt < new Date() || hash(code) !== user.emailVerificationCodeHash) {
		throw BadRequestException({ Message: "Verification code is invalid or expired" });
	}
	user.confirmEmail = new Date();
	user.emailVerificationCodeHash = undefined;
	user.emailVerificationExpiresAt = undefined;
	await user.save();
	return { verified: true };
};

export const resendVerificationEmail = async (email) => {
	const normalizedEmail = email.trim().toLowerCase();
	const user = await findOne({
		model: UserModel,
		filter: { email: normalizedEmail },
		select: "+emailVerificationCodeHash +emailVerificationResendAt",
	});
	// Use a generic success response to avoid disclosing whether an email is registered.
	if (!user || user.confirmEmail) return { accepted: true };

	if (user.emailVerificationResendAt && user.emailVerificationResendAt > new Date() && process.env.NODE_ENV !== "test") {
		throw BadRequestException({ Message: "Please wait before requesting another verification code" });
	}

	const verificationCode = String(randomInt(100000, 1000000));
	user.emailVerificationCodeHash = hash(verificationCode);
	user.emailVerificationExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
	user.emailVerificationResendAt = new Date(Date.now() + 60 * 1000);
	await user.save();
	let emailResult;
	try {
		emailResult = await sendVerificationEmail(normalizedEmail, verificationCode);
	} catch (error) {
		user.emailVerificationCodeHash = undefined;
		user.emailVerificationExpiresAt = undefined;
		user.emailVerificationResendAt = undefined;
		await user.save();
		throw error;
	}
	return {
		accepted: true,
		...(emailResult.developmentCode && { developmentVerificationCode: emailResult.developmentCode }),
	};
};

export const refreshTokens = async (token) => {
	if (!JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET is missing from environment configuration");
	let payload;
	try {
		payload = jwt.verify(token, JWT_REFRESH_SECRET, { issuer: "saraha-api", audience: "saraha-client" });
	} catch {
		throw UnauthorizedException({ Message: "Invalid or expired refresh token" });
	}
	if (payload.type !== "refresh") throw UnauthorizedException({ Message: "Invalid refresh token" });
	const user = await findOne({ model: UserModel, filter: { _id: payload.sub }, select: "+refreshTokenHash" });
	if (!user?.refreshTokenHash || user.refreshTokenHash !== hash(token) || (payload.tokenVersion ?? 0) !== (user.tokenVersion ?? 0)) {
		throw UnauthorizedException({ Message: "Refresh token has been revoked" });
	}
	return { user, ...(await createTokenPair(user)) };
};

export const googleLogin = async (idToken) => {
	if (!GOOGLE_CLIENT_ID) throw new Error("GOOGLE_CLIENT_ID is missing from environment configuration");
	const client = new OAuth2Client(GOOGLE_CLIENT_ID);
	let ticket;
	try {
		ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
	} catch {
		throw UnauthorizedException({ Message: "Invalid Google ID token" });
	}
	const profile = ticket.getPayload();
	if (!profile?.email || !profile.email_verified) {
		throw UnauthorizedException({ Message: "A verified Google email is required" });
	}
	const email = profile.email.toLowerCase();
	let user = await findOne({ model: UserModel, filter: { googleId: profile.sub } });
	if (!user) {
		user = await findOne({ model: UserModel, filter: { email } });
		if (user && user.provider === 0) {
			throw ConflictException({ Message: "Email already belongs to a password account. Sign in normally first." });
		}
	}
	if (!user) {
		const names = (profile.name || email.split("@")[0]).trim().split(/\s+/);
		user = await create({
			model: UserModel,
			data: {
				firstName: names[0] || "Google",
				lastName: names.slice(1).join(" "),
				email,
				googleId: profile.sub,
				provider: 1,
				confirmEmail: new Date(),
				profilePic: profile.picture,
			},
		});
	} else if (!user.googleId) {
		user.googleId = profile.sub;
		user.provider = 1;
		await user.save();
	}
	return { user, ...(await createTokenPair(user)) };
};

export const logout = async (userId) => {
	await findByIdAndUpdate({
		model: UserModel,
		id: userId,
		update: { $unset: { refreshTokenHash: 1 }, $inc: { tokenVersion: 1 } },
	});
	return { loggedOut: true };
};

export const forgotPassword = async (email) => {
	const normalizedEmail = email.trim().toLowerCase();
	const user = await findOne({ model: UserModel, filter: { email: normalizedEmail }, select: "+password +passwordResetTokenHash +passwordResetExpiresAt +passwordResetRequestedAt" });
	// Avoid revealing whether an account exists.
	if (!user || !user.password) return { accepted: true };
	if (user.passwordResetRequestedAt && Date.now() - user.passwordResetRequestedAt.getTime() < 60_000) {
		return { accepted: true };
	}
	const resetToken = randomBytes(32).toString("hex");
	user.passwordResetTokenHash = hash(resetToken);
	user.passwordResetExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
	user.passwordResetRequestedAt = new Date();
	await user.save();
	let emailResult;
	try {
		emailResult = await sendPasswordResetEmail(normalizedEmail, resetToken);
	} catch (error) {
		user.passwordResetTokenHash = undefined;
		user.passwordResetExpiresAt = undefined;
		user.passwordResetRequestedAt = undefined;
		await user.save();
		throw error;
	}
	return {
		accepted: true,
		...(emailResult.developmentResetToken && { developmentResetToken: emailResult.developmentResetToken }),
	};
};

export const resetPassword = async ({ token, password }) => {
	const user = await findOne({
		model: UserModel,
		filter: { passwordResetTokenHash: hash(token), passwordResetExpiresAt: { $gt: new Date() } },
		select: "+passwordResetTokenHash +passwordResetExpiresAt",
	});
	if (!user) throw BadRequestException({ Message: "Password reset token is invalid or expired" });

	user.password = await bcrypt.hash(password, 12);
	user.passwordResetTokenHash = undefined;
	user.passwordResetExpiresAt = undefined;
	user.confirmEmail = user.confirmEmail || new Date();
	user.tokenVersion = (user.tokenVersion ?? 0) + 1;
	user.refreshTokenHash = undefined;
	await user.save();
	return { passwordReset: true };
};
