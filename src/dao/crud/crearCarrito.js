import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart

const crearCarrito = async () => {
    try {
        const nuevoCarrito = new Carts({
            id: Math.floor(Math.random() * 1000), // Genera una ID aleatoria
            productos: []
        });
        await nuevoCarrito.save();
        console.log(`Carrito creado correctamente.`);
        return nuevoCarrito.id; // Retorna la ID del carrito creado
    } catch (error) {
        console.error(`Error al crear el carrito: ${error.message}`);
        return null; // Retorna null en caso de error
    }
};

// Uso de la función crearCarrito
const idCarrito = await crearCarrito();
console.log(`ID del carrito creado: ${idCarrito}`);