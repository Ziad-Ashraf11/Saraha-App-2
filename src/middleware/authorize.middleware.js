import { ForbiddenException } from "../Utils/Response/error.response.js";

export const authorize = (...allowedRoles) => (req, res, next) => {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    throw ForbiddenException({ Message: "You do not have permission to access this resource" });
  }
  next();
};
