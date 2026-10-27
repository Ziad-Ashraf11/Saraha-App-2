import { BadRequestException } from "../../Utils/Response/error.response.js";

export const validateCreateMessage = (req, res, next) => {
	if (typeof req.body?.content !== "string" || !req.body.content.trim()) {
		throw BadRequestException({ Message: "Message content is required" });
	}
	next();
};
