import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const deleteAllProducts = async () => {
    try {
        const result = await Product.deleteMany({});
        console.log(`${result.deletedCount} documentos borrados.`);
    } catch (error) {
        console.error('Error al borrar los documentos:', error);
    }
};

deleteAllProducts();