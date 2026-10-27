import nodemailer from "nodemailer";
import {
  MAIL_FROM,
  APP_BASE_URL,
  SMTP_HOST,
  SMTP_PASS,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
} from "../../config/config.service.js";

export const sendVerificationEmail = async (email, code) => {
  if (process.env.NODE_ENV === "test" || (process.env.NODE_ENV !== "production" && (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM))) {
    if (process.env.NODE_ENV !== "test") console.info(`[DEV ONLY] Email verification code for ${email}: ${code}`);
    return { delivered: false, developmentCode: code };
  }
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM) {
    throw new Error("Email delivery is not configured");
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: "Verify your Saraha account",
    text: `Your verification code is ${code}. It expires in 10 minutes.`,
    html: `<p>Your verification code is <strong>${code}</strong>.</p><p>It expires in 10 minutes.</p>`,
  });
  return { delivered: true };
};

export const sendPasswordResetEmail = async (email, resetToken) => {
  if (process.env.NODE_ENV === "test" || (process.env.NODE_ENV !== "production" && (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM))) {
    if (process.env.NODE_ENV !== "test") console.info(`[DEV ONLY] Password reset token for ${email}: ${resetToken}`);
    return { delivered: false, developmentResetToken: resetToken };
  }
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM) {
    throw new Error("Email delivery is not configured");
  }

  const resetUrl = `${APP_BASE_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: "Reset your Saraha password",
    text: `Use this link within 15 minutes to reset your password: ${resetUrl}`,
    html: `<p>Use the link below within 15 minutes to reset your password:</p><p><a href="${resetUrl}">Reset password</a></p>`,
  });
  return { delivered: true };
};
