import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const searchCarts = async () => {
    try {
        const carts = await Carts.find({});
        console.log("Lista de todos los carritos:");
        console.log(carts);
        return carts;
    } catch (error) {
        console.error(`Error al buscar carritos: ${error.message}`);
        return [];
    }
};

// Uso de la función searchCarts
searchCarts();