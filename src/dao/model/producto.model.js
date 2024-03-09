import mongoose from "mongoose";

const collectionName = 'Product';

const productoSchema = new mongoose.Schema({
    id: {
        type: Number,
        required: true,
        unique: true,
    },
    titulo: {
        type: String,
        required: true,
    },
    descripcion: {
        type: String,
        required: true,
    },
    code: {
        type: String,
        required: true,
        unique: true,
    },
    precio: {
        type: Number,
        required: true,
        min: 0, // Acepta solo valores mayores o iguales a 0
    },
    estado: {
        type: Boolean,
        required: true,
    },
    cantidad:  {
        type: Number,
        required: true,
        min: 0, // Acepta solo valores mayores o iguales a 0
        validate: {
            validator: Number.isInteger, // Valida que el valor sea un entero
            message: '{VALUE} no es un entero válido.'
        }
    },
    marca: {
        type: String,
        default: 'indeterminado', // Valor por defecto
        required: true,
    },
    categoria: {
        type: String,
        default: 'indeterminado', // Valor por defecto
        required: true,
    },
    demografia: {
        type: String,
        default: 'u', // Valor por defecto
        required: true,
        enum: ['u', 'm', 'h', 'n'], // Valores permitidos
    },
    imagen: {
        type: String,
        required: false,
    }
});
;

// producto.model.js
const Product = mongoose.model(collectionName, productoSchema);
export default Product;