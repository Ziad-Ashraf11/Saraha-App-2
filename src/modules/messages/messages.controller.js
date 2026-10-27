import {Router} from "express";
import successResponse from "../../Utils/Response/success.response.js";
import { authenticate } from "../../middleware/auth.middleware.js";
import { createMessage, deleteMyMessage, listMyMessages } from "./messages.service.js";
import { validateCreateMessage } from "./messages.validiation.js";

const router = Router();

router.post("/:receiverId", validateCreateMessage, async (req, res) => {
	const message = await createMessage(req.params.receiverId, req.body.content);
	return successResponse(res, 201, "Message sent", message);
});

router.get("/me", authenticate, async (req, res) => {
	return successResponse(res, 200, "Messages retrieved", await listMyMessages(req.user._id));
});

router.delete("/:messageId", authenticate, async (req, res) => {
	return successResponse(res, 200, "Message deleted", await deleteMyMessage(req.user._id, req.params.messageId));
});

export default router;
