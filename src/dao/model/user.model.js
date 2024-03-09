import mongoose from "mongoose";

const collectionName = 'User';

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        validate: {
            validator: function(v) {
                return v !== "adminCoder@coder.com";
            },
            message: props => `${props.value} no es un email válido.`
        }
    },
    rol: {
        type: String,
        default: "user",
        required: true,
    }
});
;

// producto.model.js
const User = mongoose.model(collectionName, userSchema);
export default User;