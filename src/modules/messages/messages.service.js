import MessageModel from "../../DB/models/message.model.js";
import UserModel from "../../DB/models/user.model.js";
import { create, findOne, find, findOneAndDelete } from "../../DB/database.repository.js";
import { NotFoundException } from "../../Utils/Response/error.response.js";

export const createMessage = async (receiverId, content) => {
	if (!(await findOne({ model: UserModel, filter: { _id: receiverId }, select: "_id", options: { lean: true } }))) {
		throw NotFoundException({ Message: "Recipient not found" });
	}
	return create({ model: MessageModel, data: { receiver: receiverId, content: content.trim() } });
};

export const listMyMessages = async (receiverId) =>
	find({
		model: MessageModel,
		filter: { receiver: receiverId },
		options: { sort: { createdAt: -1 }, lean: true },
	});

export const deleteMyMessage = async (receiverId, messageId) => {
	const message = await findOneAndDelete({
		model: MessageModel,
		filter: { _id: messageId, receiver: receiverId },
	});
	if (!message) throw NotFoundException({ Message: "Message not found" });
	return { deleted: true };
};
