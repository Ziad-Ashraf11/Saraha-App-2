import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import mongoose from "mongoose";
import UserModel from "../src/DB/models/user.model.js";
import { DB_URI } from "../config/config.service.js";

const baseUrl = process.env.API_URL || "http://localhost:3000";
const email = `auth-smoke-${randomUUID()}@example.invalid`;

const request = async (path, { method = "GET", body, token } = {}) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body && { "content-type": "application/json" }),
      ...(token && { authorization: `Bearer ${token}` }),
    },
    ...(body && { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  return { status: response.status, data };
};

const registration = await request("/api/v1/auth/register", {
  method: "POST",
  body: {
    firstName: "Auth",
    lastName: "SmokeTest",
    email,
    password: "SmokeTest123",
  },
});
assert.equal(registration.status, 201, JSON.stringify(registration.data));
assert.equal(registration.data.data.user.emailVerificationCodeHash, undefined);
const invalidRegistration = await request("/api/v1/auth/register", {
  method: "POST",
  body: { firstName: "Bad", email: "not-an-email", password: "short" },
});
assert.equal(invalidRegistration.status, 400, JSON.stringify(invalidRegistration.data));

const unverifiedLogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email, password: "SmokeTest123" },
});
assert.equal(unverifiedLogin.status, 403, JSON.stringify(unverifiedLogin.data));

const resend = await request("/api/v1/auth/resend-verification", {
  method: "POST",
  body: { email },
});
assert.equal(resend.status, 200, JSON.stringify(resend.data));
const verificationCode = resend.data.data.developmentVerificationCode;
assert.ok(verificationCode, "Test mode should return a verification code without sending email");
console.log("PASS registration, input validation, and resend verification");

const verification = await request("/api/v1/auth/verify-email", {
  method: "POST",
  body: { email, code: verificationCode },
});
assert.equal(verification.status, 200, JSON.stringify(verification.data));
console.log("PASS email verification");

const duplicateRegistration = await request("/api/v1/auth/register", {
  method: "POST",
  body: {
    firstName: "Auth",
    lastName: "SmokeTest",
    email,
    password: "SmokeTest123",
  },
});
assert.equal(duplicateRegistration.status, 409, JSON.stringify(duplicateRegistration.data));

const invalidLogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email, password: "WrongPassword123" },
});
assert.equal(invalidLogin.status, 401, JSON.stringify(invalidLogin.data));

const login = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email, password: "SmokeTest123" },
});
assert.equal(login.status, 200, JSON.stringify(login.data));
const { accessToken, refreshToken } = login.data.data;
assert.ok(accessToken);
assert.ok(refreshToken);
console.log("PASS login and token issuance");

const profile = await request("/api/v1/users/me", { token: accessToken });
assert.equal(profile.status, 200, JSON.stringify(profile.data));
assert.equal(profile.data.data.password, undefined);
console.log("PASS authenticated profile and password redaction");

const updatedProfile = await request("/api/v1/users/me", {
  method: "PATCH",
  token: accessToken,
  body: { phone: "555-0101" },
});
assert.equal(updatedProfile.status, 200, JSON.stringify(updatedProfile.data));
assert.equal(updatedProfile.data.data.phone, "555-0101");

const rejectedProfileUpdate = await request("/api/v1/users/me", {
  method: "PATCH",
  token: accessToken,
  body: { role: "ADMIN" },
});
assert.equal(rejectedProfileUpdate.status, 400, JSON.stringify(rejectedProfileUpdate.data));
console.log("PASS profile update and protected fields validation");

const unauthenticatedProfile = await request("/api/v1/users/me");
assert.equal(unauthenticatedProfile.status, 401, JSON.stringify(unauthenticatedProfile.data));

const adminCheck = await request("/api/v1/users/admin-check", { token: accessToken });
assert.equal(adminCheck.status, 403, JSON.stringify(adminCheck.data));
console.log("PASS role authorization rejects regular user");

const refreshed = await request("/api/v1/auth/refresh", {
  method: "POST",
  body: { refreshToken },
});
assert.equal(refreshed.status, 200, JSON.stringify(refreshed.data));
assert.ok(refreshed.data.data.refreshToken);
console.log("PASS refresh-token rotation");

const invalidRefresh = await request("/api/v1/auth/refresh", {
  method: "POST",
  body: { refreshToken: "invalid-token" },
});
assert.equal(invalidRefresh.status, 401, JSON.stringify(invalidRefresh.data));

const forgot = await request("/api/v1/auth/forgot-password", {
  method: "POST",
  body: { email },
});
assert.equal(forgot.status, 200, JSON.stringify(forgot.data));
const resetToken = forgot.data.data.developmentResetToken;
assert.ok(resetToken, "Test mode should return a reset token without sending email");
console.log("PASS forgot-password request; test mode returned reset token safely");

const reset = await request("/api/v1/auth/reset-password", {
  method: "POST",
  body: { token: resetToken, password: "SmokeTest456" },
});
assert.equal(reset.status, 200, JSON.stringify(reset.data));
console.log("PASS reset password");

const unknownForgot = await request("/api/v1/auth/forgot-password", {
  method: "POST",
  body: { email: `unknown-${randomUUID()}@example.invalid` },
});
assert.equal(unknownForgot.status, 200, JSON.stringify(unknownForgot.data));

const revokedAccess = await request("/api/v1/users/me", { token: refreshed.data.data.accessToken });
assert.equal(revokedAccess.status, 401, JSON.stringify(revokedAccess.data));

const newPasswordLogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email, password: "SmokeTest456" },
});
assert.equal(newPasswordLogin.status, 200, JSON.stringify(newPasswordLogin.data));
console.log("PASS reset invalidates existing sessions and new password works");

const revokedSession = await request("/api/v1/auth/revoke-token", {
  method: "POST",
  body: { refreshToken: newPasswordLogin.data.data.refreshToken },
});
assert.equal(revokedSession.status, 200, JSON.stringify(revokedSession.data));
assert.equal(revokedSession.data.data.revoked, true);
const revokedSessionProfile = await request("/api/v1/users/me", {
  token: newPasswordLogin.data.data.accessToken,
});
assert.equal(revokedSessionProfile.status, 401, JSON.stringify(revokedSessionProfile.data));
console.log("PASS explicit token revocation");

const relogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email, password: "SmokeTest456" },
});
assert.equal(relogin.status, 200, JSON.stringify(relogin.data));

const logout = await request("/api/v1/auth/logout", {
  method: "POST",
  token: relogin.data.data.accessToken,
});
assert.equal(logout.status, 200, JSON.stringify(logout.data));

const loggedOutRefresh = await request("/api/v1/auth/refresh", {
  method: "POST",
  body: { refreshToken: relogin.data.data.refreshToken },
});
assert.equal(loggedOutRefresh.status, 401, JSON.stringify(loggedOutRefresh.data));
console.log("PASS logout revokes refresh token");

const twoFactorEmail = `two-factor-${randomUUID()}@example.invalid`;
const twoFactorRegistration = await request("/api/v1/auth/register", {
  method: "POST",
  body: {
    firstName: "TwoFactor",
    lastName: "Tester",
    email: twoFactorEmail,
    password: "TwoFactor123",
  },
});
assert.equal(twoFactorRegistration.status, 201, JSON.stringify(twoFactorRegistration.data));
const twoFactorVerification = await request("/api/v1/auth/verify-email", {
  method: "POST",
  body: {
    email: twoFactorEmail,
    code: twoFactorRegistration.data.data.developmentVerificationCode,
  },
});
assert.equal(twoFactorVerification.status, 200, JSON.stringify(twoFactorVerification.data));
const twoFactorInitialLogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email: twoFactorEmail, password: "TwoFactor123" },
});
assert.equal(twoFactorInitialLogin.status, 200, JSON.stringify(twoFactorInitialLogin.data));
const twoFactorAccessToken = twoFactorInitialLogin.data.data.accessToken;

const unauthenticatedEnable = await request("/api/v1/auth/2fa/enable", { method: "POST" });
assert.equal(unauthenticatedEnable.status, 401, JSON.stringify(unauthenticatedEnable.data));

const setupRequest = await request("/api/v1/auth/2fa/enable", {
  method: "POST",
  token: twoFactorAccessToken,
});
assert.equal(setupRequest.status, 200, JSON.stringify(setupRequest.data));
let setupCode = setupRequest.data.data.developmentVerificationCode;
assert.match(setupCode, /^\d{6}$/);

for (let attempt = 1; attempt <= 5; attempt += 1) {
  const invalidSetupCode = await request("/api/v1/auth/2fa/enable/confirm", {
    method: "POST",
    token: twoFactorAccessToken,
    body: { code: "000000" },
  });
  assert.equal(invalidSetupCode.status, 400, JSON.stringify(invalidSetupCode.data));
}
const exhaustedSetupCode = await request("/api/v1/auth/2fa/enable/confirm", {
  method: "POST",
  token: twoFactorAccessToken,
  body: { code: setupCode },
});
assert.equal(exhaustedSetupCode.status, 400, JSON.stringify(exhaustedSetupCode.data));

const replacementSetupRequest = await request("/api/v1/auth/2fa/enable", {
  method: "POST",
  token: twoFactorAccessToken,
});
assert.equal(replacementSetupRequest.status, 200, JSON.stringify(replacementSetupRequest.data));
setupCode = replacementSetupRequest.data.data.developmentVerificationCode;

const enabledTwoFactor = await request("/api/v1/auth/2fa/enable/confirm", {
  method: "POST",
  token: twoFactorAccessToken,
  body: { code: setupCode },
});
assert.equal(enabledTwoFactor.status, 200, JSON.stringify(enabledTwoFactor.data));
assert.equal(enabledTwoFactor.data.data.twoFactorEnabled, true);

const duplicateEnable = await request("/api/v1/auth/2fa/enable", {
  method: "POST",
  token: twoFactorAccessToken,
});
assert.equal(duplicateEnable.status, 409, JSON.stringify(duplicateEnable.data));

const twoFactorProfile = await request("/api/v1/users/me", { token: twoFactorAccessToken });
assert.equal(twoFactorProfile.status, 200, JSON.stringify(twoFactorProfile.data));
assert.equal(twoFactorProfile.data.data.twoFactorEnabled, true);
console.log("PASS authenticated two-step setup, OTP validation, and enabled state");

const loginChallenge = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email: twoFactorEmail, password: "TwoFactor123" },
});
assert.equal(loginChallenge.status, 200, JSON.stringify(loginChallenge.data));
assert.equal(loginChallenge.data.data.twoFactorVerificationRequired, true);
assert.equal(loginChallenge.data.data.accessToken, undefined);
assert.equal(loginChallenge.data.data.refreshToken, undefined);
let loginCode = loginChallenge.data.data.developmentVerificationCode;
assert.match(loginCode, /^\d{6}$/);

const invalidLoginCodeShape = await request("/api/v1/auth/2fa/login/confirm", {
  method: "POST",
  body: { email: twoFactorEmail, code: "bad" },
});
assert.equal(invalidLoginCodeShape.status, 400, JSON.stringify(invalidLoginCodeShape.data));

for (let attempt = 1; attempt <= 5; attempt += 1) {
  const invalidLoginCode = await request("/api/v1/auth/2fa/login/confirm", {
    method: "POST",
    body: { email: twoFactorEmail, code: "000000" },
  });
  assert.equal(invalidLoginCode.status, 400, JSON.stringify(invalidLoginCode.data));
}
const exhaustedLoginCode = await request("/api/v1/auth/2fa/login/confirm", {
  method: "POST",
  body: { email: twoFactorEmail, code: loginCode },
});
assert.equal(exhaustedLoginCode.status, 400, JSON.stringify(exhaustedLoginCode.data));

const replacementLoginChallenge = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email: twoFactorEmail, password: "TwoFactor123" },
});
assert.equal(replacementLoginChallenge.status, 200, JSON.stringify(replacementLoginChallenge.data));
loginCode = replacementLoginChallenge.data.data.developmentVerificationCode;

const confirmedLogin = await request("/api/v1/auth/2fa/login/confirm", {
  method: "POST",
  body: { email: twoFactorEmail, code: loginCode },
});
assert.equal(confirmedLogin.status, 200, JSON.stringify(confirmedLogin.data));
assert.ok(confirmedLogin.data.data.accessToken);
assert.ok(confirmedLogin.data.data.refreshToken);

const reusedLoginCode = await request("/api/v1/auth/2fa/login/confirm", {
  method: "POST",
  body: { email: twoFactorEmail, code: loginCode },
});
assert.equal(reusedLoginCode.status, 400, JSON.stringify(reusedLoginCode.data));
console.log("PASS login requires a one-time email OTP before token issuance");

const lockEmail = `login-lock-${randomUUID()}@example.invalid`;
const lockRegistration = await request("/api/v1/auth/register", {
  method: "POST",
  body: { firstName: "Lock", lastName: "Tester", email: lockEmail, password: "LockTest123" },
});
assert.equal(lockRegistration.status, 201, JSON.stringify(lockRegistration.data));
const lockVerification = await request("/api/v1/auth/verify-email", {
  method: "POST",
  body: { email: lockEmail, code: lockRegistration.data.data.developmentVerificationCode },
});
assert.equal(lockVerification.status, 200, JSON.stringify(lockVerification.data));

for (let attempt = 1; attempt <= 5; attempt += 1) {
  const failedLogin = await request("/api/v1/auth/login", {
    method: "POST",
    body: { email: lockEmail, password: "IncorrectPassword123" },
  });
  assert.equal(failedLogin.status, attempt === 5 ? 403 : 401, JSON.stringify(failedLogin.data));
}
const lockedLogin = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email: lockEmail, password: "LockTest123" },
});
assert.equal(lockedLogin.status, 403, JSON.stringify(lockedLogin.data));
assert.equal(lockedLogin.data.extra.retryAfterSeconds, 300);
console.log("PASS five consecutive failures block correct-password login for five minutes");

await mongoose.connect(DB_URI);
try {
  const lockedUser = await UserModel.findOne({ email: lockEmail }).select("+loginLockedUntil +loginFailedAttempts");
  assert.ok(lockedUser?.loginLockedUntil, "Lock expiration must be persisted");
  assert.ok(lockedUser.loginLockedUntil.getTime() >= Date.now() + 4 * 60 * 1000);
  assert.ok(lockedUser.loginLockedUntil.getTime() <= Date.now() + 5 * 60 * 1000);
  await UserModel.updateOne({ _id: lockedUser._id }, { $set: { loginLockedUntil: new Date(Date.now() - 1000) } });
} finally {
  await mongoose.disconnect();
}

const loginAfterExpiredLock = await request("/api/v1/auth/login", {
  method: "POST",
  body: { email: lockEmail, password: "LockTest123" },
});
assert.equal(loginAfterExpiredLock.status, 200, JSON.stringify(loginAfterExpiredLock.data));
assert.ok(loginAfterExpiredLock.data.data.accessToken);
console.log("PASS login works after the five-minute lock expires");

const invalidGoogleLogin = await request("/api/v1/auth/google", {
  method: "POST",
  body: {},
});
assert.equal(invalidGoogleLogin.status, 400, JSON.stringify(invalidGoogleLogin.data));
