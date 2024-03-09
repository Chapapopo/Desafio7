import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const deleteProductsPorId = async (idProducto) => {
    try {
        const result = await Product.deleteOne({ id: idProducto });
        if (result.deletedCount === 0) {
            console.error(`No se encontró un producto con id ${idProducto}.`);
            return;
        }
        console.log(`Producto con id ${idProducto} eliminado.`);
    } catch (error) {
        console.error(`Error al eliminar el producto: ${error.message}`);
    }
};

// Uso de la función deleteProductsPorId
const idProducto = 1; // ID del producto que se quiere eliminar
deleteProductsPorId(idProducto);