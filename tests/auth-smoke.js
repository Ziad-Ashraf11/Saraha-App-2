import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

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

const invalidGoogleLogin = await request("/api/v1/auth/google", {
  method: "POST",
  body: {},
});
assert.equal(invalidGoogleLogin.status, 400, JSON.stringify(invalidGoogleLogin.data));
