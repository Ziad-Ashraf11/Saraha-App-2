import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { unlink } from "node:fs/promises";
import { resolve } from "node:path";

const baseUrl = process.env.API_URL || "http://localhost:3000";
const email = `upload-smoke-${randomUUID()}@example.invalid`;

const postJson = async (path, body, token) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token && { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
};

const registration = await postJson("/api/v1/auth/register", {
  firstName: "Upload",
  lastName: "Tester",
  email,
  password: "UploadTest123",
});
assert.equal(registration.status, 201, JSON.stringify(registration.body));
const code = registration.body.data.developmentVerificationCode;
assert.ok(code, "Upload test expects test mode to return email codes");

const verification = await postJson("/api/v1/auth/verify-email", { email, code });
assert.equal(verification.status, 200, JSON.stringify(verification.body));
const login = await postJson("/api/v1/auth/login", { email, password: "UploadTest123" });
assert.equal(login.status, 200, JSON.stringify(login.body));
const token = login.body.data.accessToken;
const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0]);

const unauthenticatedForm = new FormData();
unauthenticatedForm.append("image", new Blob([png], { type: "image/png" }), "tiny.png");
const unauthenticatedUpload = await fetch(`${baseUrl}/api/v1/users/me/profile-image`, {
  method: "POST",
  body: unauthenticatedForm,
});
assert.equal(unauthenticatedUpload.status, 401);

const form = new FormData();
form.append("image", new Blob([png], { type: "image/png" }), "tiny.png");
const upload = await fetch(`${baseUrl}/api/v1/users/me/profile-image`, {
  method: "POST",
  headers: { authorization: `Bearer ${token}` },
  body: form,
});
const uploadBody = await upload.json();
assert.equal(upload.status, 200, JSON.stringify(uploadBody));
assert.match(uploadBody.data.profilePic, /^\/uploads\/[\w-]+\.png$/);
console.log("PASS authenticated image upload and profile update");
const profilePath = resolve("uploads", uploadBody.data.profilePic.slice("/uploads/".length));

const imageResponse = await fetch(`${baseUrl}${uploadBody.data.profilePic}`);
assert.equal(imageResponse.status, 200);
assert.equal(imageResponse.headers.get("content-type"), "image/png");
console.log("PASS uploaded image is served");

const coverForm = new FormData();
coverForm.append("image", new Blob([png], { type: "image/png" }), "cover.png");
const coverUpload = await fetch(`${baseUrl}/api/v1/users/me/cover-image`, {
  method: "POST",
  headers: { authorization: `Bearer ${token}` },
  body: coverForm,
});
const coverBody = await coverUpload.json();
assert.equal(coverUpload.status, 200, JSON.stringify(coverBody));
assert.match(coverBody.data.coverPic, /^\/uploads\/[\w-]+\.png$/);
console.log("PASS authenticated cover image upload");
const coverPath = resolve("uploads", coverBody.data.coverPic.slice("/uploads/".length));

const fakeImage = new FormData();
fakeImage.append("image", new Blob(["not really a png"], { type: "image/png" }), "fake.png");
const rejected = await fetch(`${baseUrl}/api/v1/users/me/profile-image`, {
  method: "POST",
  headers: { authorization: `Bearer ${token}` },
  body: fakeImage,
});
assert.equal(rejected.status, 400);
console.log("PASS image content signature validation");

const unsupportedFile = new FormData();
unsupportedFile.append("image", new Blob(["plain text"], { type: "text/plain" }), "notes.txt");
const unsupportedResponse = await fetch(`${baseUrl}/api/v1/users/me/profile-image`, {
  method: "POST",
  headers: { authorization: `Bearer ${token}` },
  body: unsupportedFile,
});
assert.equal(unsupportedResponse.status, 400);
console.log("PASS unsupported upload content type is rejected");

await Promise.all([profilePath, coverPath].map((filePath) => unlink(filePath).catch(() => {})));
