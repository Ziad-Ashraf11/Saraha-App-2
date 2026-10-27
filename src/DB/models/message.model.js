import mongoose, { Schema } from "mongoose";

const messageSchema = new Schema(
  {
    receiver: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    content: {
      type: String,
      required: [true, "Message content is required"],
      trim: true,
      minLength: 1,
      maxLength: 2000,
    },
  },
  { timestamps: true },
);

const MessageModel = mongoose.model("Message", messageSchema);

export default MessageModel;
