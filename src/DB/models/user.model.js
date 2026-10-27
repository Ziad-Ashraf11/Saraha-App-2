import mongoose, { Schema } from "mongoose";
import { GenderEnum, RoleEnum, ProviderEnum } from "../../Utils/enums/user.enum.js";

const userSchema = new Schema(
  {
    firstName: {
      type: String,
      required: [true, "first name is mandatory"],
      minLength: 2,
      maxLength: 25,
      trim: true,
    },
    lastName: {
      type: String,
      minLength: 2,
      maxLength: 25,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      required: true,
    },
    password: {
      type: String,
      required: function passwordRequiredForSystemProvider() {
        return this.provider === ProviderEnum.SYSTEM;
      },
      select: false,
    },
    googleId: { type: String, unique: true, sparse: true },
    emailVerificationCodeHash: { type: String, select: false },
    emailVerificationExpiresAt: { type: Date, select: false },
    emailVerificationResendAt: { type: Date, select: false },
    loginFailedAttempts: { type: Number, default: 0, select: false },
    loginLockedUntil: { type: Date, select: false },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSetupCodeHash: { type: String, select: false },
    twoFactorSetupCodeExpiresAt: { type: Date, select: false },
    twoFactorSetupCodeAttempts: { type: Number, default: 0, select: false },
    twoFactorLoginCodeHash: { type: String, select: false },
    twoFactorLoginCodeExpiresAt: { type: Date, select: false },
    twoFactorLoginCodeAttempts: { type: Number, default: 0, select: false },
    refreshTokenHash: { type: String, select: false },
    tokenVersion: { type: Number, default: 0 },
    passwordResetTokenHash: { type: String, select: false },
    passwordResetExpiresAt: { type: Date, select: false },
    passwordResetRequestedAt: { type: Date, select: false },
    DOB: Date,
    age: Number,
    phone: String,
    gender: {
      type: String,
      enum: Object.values(GenderEnum),
      default: GenderEnum.MALE,
    },
    role: {
      type: String,
      enum: Object.values(RoleEnum),
      default: RoleEnum.USER,
    },
    provider: {
      type: Number,
      enum: Object.values(ProviderEnum),
      default: ProviderEnum.SYSTEM,
    },
    confirmEmail: Date,
    profilePic: String,
    coverPic: String,
    avatarStorageName: { type: String, select: false },
    coverStorageName: { type: String, select: false },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(_doc, ret) {
        delete ret.password;
        delete ret.emailVerificationCodeHash;
        delete ret.emailVerificationExpiresAt;
        delete ret.emailVerificationResendAt;
        delete ret.loginFailedAttempts;
        delete ret.loginLockedUntil;
        delete ret.twoFactorSetupCodeHash;
        delete ret.twoFactorSetupCodeExpiresAt;
        delete ret.twoFactorSetupCodeAttempts;
        delete ret.twoFactorLoginCodeHash;
        delete ret.twoFactorLoginCodeExpiresAt;
        delete ret.twoFactorLoginCodeAttempts;
        delete ret.refreshTokenHash;
        delete ret.passwordResetTokenHash;
        delete ret.passwordResetExpiresAt;
        delete ret.passwordResetRequestedAt;
        delete ret.googleId;
        delete ret.tokenVersion;
        delete ret.avatarStorageName;
        delete ret.coverStorageName;
        return ret;
      },
    },
    toObject: { virtuals: true },
    optimisticConcurrency: true,
  },
);


userSchema
  .virtual("username")
  .set(function (value) {
    const [firstName = "", ...lastNameParts] = String(value ?? "")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    const lastName = lastNameParts.join(" ");
    this.set({ firstName, lastName });
  })
  .get(function () {
    return [this.firstName, this.lastName].filter(Boolean).join(" ");
  });

const UserModel = mongoose.model("User", userSchema);

export default UserModel;