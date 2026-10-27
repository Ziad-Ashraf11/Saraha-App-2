import UserModel from "../../DB/models/user.model.js";
import { findById, findByIdAndUpdate } from "../../DB/database.repository.js";
import { NotFoundException } from "../../Utils/Response/error.response.js";

export const getProfile = async (userId) => {
	const user = await findById({ model: UserModel, id: userId });
	if (!user) throw NotFoundException({ Message: "User not found" });
	return user;
};

export const updateProfile = async (userId, updates) => {
	const user = await findByIdAndUpdate({
		model: UserModel,
		id: userId,
		update: updates,
		options: {
			returnDocument: "after",
			runValidators: true,
		},
	});
	if (!user) throw NotFoundException({ Message: "User not found" });
	return user;
};

export const getUserForImageCleanup = async (userId) =>
	findById({ model: UserModel, id: userId, select: "+avatarStorageName +coverStorageName" });
