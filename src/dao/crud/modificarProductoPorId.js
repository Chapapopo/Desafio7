import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const modificarProductoPorId = async (id, campo, valor) => {
    try {
        if (campo === 'id' || campo === 'code') {
            console.error(`No se puede modificar el campo ${campo}.`);
            return;
        }

        const update = { [campo]: valor };
        const producto = await Product.findOneAndUpdate({ id: id }, update, { new: true });
        if (!producto) {
            console.error(`No se encontró un producto con id ${id}.`);
            return;
        }
        console.log(`Producto con id ${id} modificado correctamente.`);
    } catch (error) {
        console.error(`Error al modificar el producto con id ${id}: ${error.message}`);
    }
};

// Uso de la función modificarProductoPorId
const idProductoAModificar = 1; // ID del producto que se quiere modificar
const campoAModificar = "precio"; // Campo que se quiere modificar
const nuevoValor = 99.99; // Nuevo valor para el campo

modificarProductoPorId(idProductoAModificar, campoAModificar, nuevoValor);