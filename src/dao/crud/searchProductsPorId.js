import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const searchProductsPorId = async (idProducto) => {
    try {
        const product = await Product.findOne({ id: idProducto });
        if (!product) {
            console.error(`No se encontró un producto con id ${idProducto}.`);
            return null;
        }

        console.log("Producto encontrado:");
        console.log(product);
        return product;
    } catch (error) {
        console.error(`Error al buscar el producto: ${error.message}`);
        return null;
    }
};

// Uso de la función searchProductsPorId
const idProducto = 2; // ID del producto que se quiere buscar
searchProductsPorId(idProducto);