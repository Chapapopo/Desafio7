import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const modificarCarritoPorId = async (idCar, idPro, campo, nuevoValor) => {
    try {
        // Definir el filtro para encontrar el carrito por su id y el producto por su id en el array de productos
        const filter = { id: idCar, "products.id": idPro };

        // Definir la actualización para modificar el campo del producto
        const update = { $set: { [`products.$.${campo}`]: nuevoValor } };

        // Realizar la actualización
        const carritoActualizado = await Carts.findOneAndUpdate(filter, update, { new: true });

        if (!carritoActualizado) {
            console.error(`No se encontró un carrito con id ${idCar} o un producto con id ${idPro} en el carrito.`);
            return;
        }

        console.log(`Producto con id ${idPro} en el carrito con id ${idCar} actualizado.`);
    } catch (error) {
        console.error(`Error al modificar el producto en el carrito: ${error.message}`);
    }
};

// Uso de la función modificarCarritoPorId
const idCarrito = 88; // ID del carrito que se quiere modificar
const idProducto = 1; // ID del producto que se quiere modificar
const campo = 'cantidad'; // Campo que se quiere modificar
const nuevoValor = 9; // Nuevo valor para el campo
modificarCarritoPorId(idCarrito, idProducto, campo, nuevoValor);