import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const deleteCarritoPorId = async (idCarrito) => {
    try {
        // Buscar el carrito por su id
        const carrito = await Carts.findOne({ id: idCarrito });
        if (!carrito) {
            console.error(`No se encontró un carrito con id ${idCarrito}.`);
            return;
        }

        // Eliminar el carrito de la base de datos
        await Carts.deleteOne({ id: idCarrito });
        console.log(`Carrito con id ${idCarrito} eliminado.`);
    } catch (error) {
        console.error(`Error al eliminar el carrito: ${error.message}`);
    }
};

// Uso de la función deleteCarritoPorId
const idCarrito = 328; // ID del carrito que se quiere eliminar
deleteCarritoPorId(idCarrito);