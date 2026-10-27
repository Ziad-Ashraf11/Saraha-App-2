import mongoose from "mongoose";
import { DB_URI } from "../../config/config.service.js";

const connectDB = async () => {
    try {
        await mongoose.connect(DB_URI, {
            serverSelectionTimeoutMS: 5000,
        });
        console.log("MongoDB connected successfully");
    } catch (error) {
        console.error("MongoDB failed to connect:", error);
        throw error;
    }
}

export default connectDB;