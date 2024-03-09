import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const searchCartsPorId = async (idCarrito) => {
    try {
        const carrito = await Carts.findOne({ id: idCarrito });
        if (!carrito) {
            console.error(`No se encontró un carrito con id ${idCarrito}.`);
            return null;
        }

        console.log("Carrito encontrado:");
        console.log(carrito);
        return carrito;
    } catch (error) {
        console.error(`Error al buscar el carrito: ${error.message}`);
        return null;
    }
};

// Uso de la función searchCartsPorId
const idCarrito = 480; // ID del carrito que se quiere buscar
searchCartsPorId(idCarrito);