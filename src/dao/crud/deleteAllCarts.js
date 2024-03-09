import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const deleteAllCarts = async () => {
    try {
        // Eliminar todos los carritos de la base de datos
        await Carts.deleteMany({});
        console.log("Todos los carritos han sido eliminados.");
    } catch (error) {
        console.error(`Error al eliminar los carritos: ${error.message}`);
    }
};

// Uso de la función deleteAllCarts
deleteAllCarts();