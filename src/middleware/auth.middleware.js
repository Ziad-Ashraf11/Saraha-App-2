import jwt from "jsonwebtoken";
import UserModel from "../DB/models/user.model.js";
import { findById } from "../DB/database.repository.js";
import { JWT_SECRET } from "../../config/config.service.js";
import { UnauthorizedException } from "../Utils/Response/error.response.js";

export const authenticate = async (req, res, next) => {
  const authorization = req.headers.authorization;
  const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : null;
  if (!token || !JWT_SECRET) {
    throw UnauthorizedException({ Message: "A valid bearer token is required" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: "saraha-api",
      audience: "saraha-client",
    });
    if (payload.type !== "access") {
      throw UnauthorizedException({ Message: "An access token is required" });
    }
    const user = await findById({ model: UserModel, id: payload.sub });
    if (!user) throw UnauthorizedException({ Message: "User no longer exists" });
    if ((payload.tokenVersion ?? 0) !== (user.tokenVersion ?? 0)) {
      throw UnauthorizedException({ Message: "Token has been revoked" });
    }
    req.user = user;
    next();
  } catch (error) {
    if (error.status) throw error;
    throw UnauthorizedException({ Message: "Invalid or expired token" });
  }
};
