import mongoose from "mongoose";

const collectionName = "Carts";

const cartSchema = new mongoose.Schema({
    id: {
        type: Number,
        required: true,
        unique: true,
    },
    products: {
        type: Array,
        require: true,
    }
});

const Carts = mongoose.model(collectionName, cartSchema)
export default Carts;