import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const deleteProductoDelCarritoPorId = async (idCarrito, idProducto) => {
    try {
        // Obtener el carrito por su id
        const carrito = await Carts.findOne({ id: idCarrito });
        if (!carrito) {
            console.error(`No se encontró un carrito con id ${idCarrito}.`);
            return;
        }

        // Eliminar el producto del carrito por su id
        carrito.products = carrito.products.filter(prod => prod.id !== idProducto);

        // Guardar el carrito actualizado en la base de datos
        await carrito.save();
        console.log(`Producto con id ${idProducto} eliminado del carrito con id ${idCarrito}.`);
    } catch (error) {
        console.error(`Error al eliminar el producto del carrito: ${error.message}`);
    }
};

// Uso de la función deleteProductoPorId
const idCarrito = 552; // ID del carrito del que se quiere eliminar el producto
const idProducto = 1; // ID del producto que se quiere eliminar
deleteProductoDelCarritoPorId(idCarrito, idProducto);