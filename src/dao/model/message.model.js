import mongoose from "mongoose";

const collectionName = "Message";

const messageSchema = new mongoose.Schema({
    user: {
        type: String,
        require: true,
    },
    message: {
        type: String,
        require: true,
    }
});

const messageModel = mongoose.model(collectionName, messageSchema)
module.exports = messageModel;