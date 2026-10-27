import {
    authRoutes,
    userRoutes,
    messagesRoutes
} from "./modules/index.js";

import successResponse from "./Utils/Response/success.response.js";
import { NotFoundException, glopalErrorHandler } from "./Utils/Response/error.response.js";
import  connectDB  from "./DB/connection.js";
import { resolve } from "node:path";

const bootstrap = async (app, express) => {
    app.use(express.json({ limit: "1mb" }));
    app.use(express.urlencoded({ extended: true }));
    app.use(express.static("public", { dotfiles: "deny", index: false }));
    app.use("/uploads", express.static("uploads", { dotfiles: "deny", index: false }));
    await connectDB();

    app.get("/", (req, res) => {
        successResponse(res, 200, "Welcome to Saraha API");
    });

    app.get("/reset-password", (req, res) => {
        res.sendFile(resolve("public/reset-password.html"));
    });

    app.use("/api/v1/auth", authRoutes);
    app.use("/api/v1/users", userRoutes);
    app.use("/api/v1/messages", messagesRoutes);

    app.all("/*dummy", (req, res) => {
        throw NotFoundException({
            Message: "Route not found",
            extra: { path: req.originalUrl, method: req.method },
        });
    });

    app.use(glopalErrorHandler);
};

export default bootstrap;