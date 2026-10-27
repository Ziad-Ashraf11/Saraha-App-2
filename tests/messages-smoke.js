import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const baseUrl = process.env.API_URL || "http://localhost:3000";

const request = async (path, { method = "GET", body, token } = {}) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body && { "content-type": "application/json" }),
      ...(token && { authorization: `Bearer ${token}` }),
    },
    ...(body && { body: JSON.stringify(body) }),
  });
  return { status: response.status, data: await response.json() };
};

const createUser = async (label) => {
  const email = `messages-${label}-${randomUUID()}@example.invalid`;
  const registration = await request("/api/v1/auth/register", {
    method: "POST",
    body: {
      firstName: "Message",
      lastName: label,
      email,
      password: "MessageTest123",
    },
  });
  assert.equal(registration.status, 201, JSON.stringify(registration.data));

  const verification = await request("/api/v1/auth/verify-email", {
    method: "POST",
    body: { email, code: registration.data.data.developmentVerificationCode },
  });
  assert.equal(verification.status, 200, JSON.stringify(verification.data));

  const login = await request("/api/v1/auth/login", {
    method: "POST",
    body: { email, password: "MessageTest123" },
  });
  assert.equal(login.status, 200, JSON.stringify(login.data));
  return {
    id: registration.data.data.user._id,
    token: login.data.data.accessToken,
  };
};

const receiver = await createUser("Receiver");
const sender = await createUser("Sender");

const unauthenticatedMessages = await request("/api/v1/messages/me");
assert.equal(unauthenticatedMessages.status, 401, JSON.stringify(unauthenticatedMessages.data));

const emptyMessage = await request(`/api/v1/messages/${receiver.id}`, {
  method: "POST",
  body: { content: "   " },
});
assert.equal(emptyMessage.status, 400, JSON.stringify(emptyMessage.data));

const missingMessageContent = await request(`/api/v1/messages/${receiver.id}`, {
  method: "POST",
  body: {},
});
assert.equal(missingMessageContent.status, 400, JSON.stringify(missingMessageContent.data));

const tooLongMessage = await request(`/api/v1/messages/${receiver.id}`, {
  method: "POST",
  body: { content: "x".repeat(2001) },
});
assert.equal(tooLongMessage.status, 400, JSON.stringify(tooLongMessage.data));

const missingRecipient = await request(`/api/v1/messages/${randomUUID().replaceAll("-", "").slice(0, 24)}`, {
  method: "POST",
  body: { content: "Hello" },
});
assert.equal(missingRecipient.status, 404, JSON.stringify(missingRecipient.data));

const invalidRecipient = await request("/api/v1/messages/not-an-object-id", {
  method: "POST",
  body: { content: "Hello" },
});
assert.equal(invalidRecipient.status, 400, JSON.stringify(invalidRecipient.data));

const sent = await request(`/api/v1/messages/${receiver.id}`, {
  method: "POST",
  body: { content: "  Hello there  " },
});
assert.equal(sent.status, 201, JSON.stringify(sent.data));
assert.equal(sent.data.data.content, "Hello there");
const messageId = sent.data.data._id;
console.log("PASS public message creation and input validation");

const senderMessages = await request("/api/v1/messages/me", { token: sender.token });
assert.equal(senderMessages.status, 200, JSON.stringify(senderMessages.data));
assert.deepEqual(senderMessages.data.data, []);

const receiverMessages = await request("/api/v1/messages/me", { token: receiver.token });
assert.equal(receiverMessages.status, 200, JSON.stringify(receiverMessages.data));
assert.equal(receiverMessages.data.data.length, 1);
assert.equal(receiverMessages.data.data[0]._id, messageId);
assert.equal(receiverMessages.data.data[0].content, "Hello there");
console.log("PASS authenticated message list is scoped to the recipient");

const senderCannotDelete = await request(`/api/v1/messages/${messageId}`, {
  method: "DELETE",
  token: sender.token,
});
assert.equal(senderCannotDelete.status, 404, JSON.stringify(senderCannotDelete.data));

const invalidDeleteId = await request("/api/v1/messages/not-an-object-id", {
  method: "DELETE",
  token: receiver.token,
});
assert.equal(invalidDeleteId.status, 400, JSON.stringify(invalidDeleteId.data));

const deleted = await request(`/api/v1/messages/${messageId}`, {
  method: "DELETE",
  token: receiver.token,
});
assert.equal(deleted.status, 200, JSON.stringify(deleted.data));
assert.equal(deleted.data.data.deleted, true);

const missingDelete = await request(`/api/v1/messages/${messageId}`, {
  method: "DELETE",
  token: receiver.token,
});
assert.equal(missingDelete.status, 404, JSON.stringify(missingDelete.data));

const emptyInbox = await request("/api/v1/messages/me", { token: receiver.token });
assert.equal(emptyInbox.status, 200, JSON.stringify(emptyInbox.data));
assert.deepEqual(emptyInbox.data.data, []);
console.log("PASS message deletion authorization and inbox update");
