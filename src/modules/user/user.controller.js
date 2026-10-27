import {Router} from "express";
import successResponse from "../../Utils/Response/success.response.js";
import { authenticate } from "../../middleware/auth.middleware.js";
import { getProfile, updateProfile } from "./user.service.js";
import { validateProfileUpdate } from "./user.validiation.js";
import { authorize } from "../../middleware/authorize.middleware.js";
import { removeStoredImage, uploadProfileImage } from "../../middleware/upload.middleware.js";
import { getUserForImageCleanup } from "./user.service.js";

const router = Router();

router.get("/me", authenticate, async (req, res) => {
	return successResponse(res, 200, "Profile retrieved", await getProfile(req.user._id));
});

router.patch("/me", authenticate, validateProfileUpdate, async (req, res) => {
	return successResponse(res, 200, "Profile updated", await updateProfile(req.user._id, req.body));
});

router.post("/me/profile-image", authenticate, uploadProfileImage, async (req, res) => {
	const existing = await getUserForImageCleanup(req.user._id);
	let user;
	try {
		user = await updateProfile(req.user._id, {
			profilePic: req.uploadedImagePath,
			avatarStorageName: req.uploadedImageName,
		});
	} catch (error) {
		await removeStoredImage(req.uploadedImageName);
		throw error;
	}
	await removeStoredImage(existing?.avatarStorageName);
	return successResponse(res, 200, "Profile image uploaded", user);
});

router.post("/me/cover-image", authenticate, uploadProfileImage, async (req, res) => {
	const existing = await getUserForImageCleanup(req.user._id);
	let user;
	try {
		user = await updateProfile(req.user._id, {
			coverPic: req.uploadedImagePath,
			coverStorageName: req.uploadedImageName,
		});
	} catch (error) {
		await removeStoredImage(req.uploadedImageName);
		throw error;
	}
	await removeStoredImage(existing?.coverStorageName);
	return successResponse(res, 200, "Cover image uploaded", user);
});

router.get("/admin-check", authenticate, authorize("ADMIN"), async (req, res) => {
	return successResponse(res, 200, "Admin authorization successful", { userId: req.user._id });
});

export default router;
