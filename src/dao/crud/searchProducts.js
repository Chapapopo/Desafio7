import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const searchProducts = async () => {
    // Buscar todos los productos
    const products = await Product.find({});
    console.log(products)
    return products;
};

searchProducts();