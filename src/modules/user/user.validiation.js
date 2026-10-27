import { BadRequestException } from "../../Utils/Response/error.response.js";

export const validateProfileUpdate = (req, res, next) => {
	const allowed = ["firstName", "lastName", "DOB", "phone", "gender", "profilePic", "coverPic"];
	const keys = Object.keys(req.body ?? {});
	if (!keys.length || keys.some((key) => !allowed.includes(key))) {
		throw BadRequestException({ Message: "Provide profile fields only" });
	}
	next();
};
