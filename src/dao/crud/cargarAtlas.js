import '../../connection.js'; // Importa el archivo de conexión
import fs from 'fs';
import Product from '../model/producto.model.js'; // Importa el modelo Product

const cargarAtlas = async () => {
    let contador = 0;
    try {
        const data = fs.readFileSync('./src/dao/productos.json', 'utf8');
        const jsonData = JSON.parse(data);
        const products = jsonData.productos;

        for (const product of products) {
            try {
                const nuevoProducto = new Product({
                    id: product.id,
                    titulo: product.titulo,
                    descripcion: product.descripcion,
                    code: product.code,
                    precio: product.precio,
                    estado: product.estado,
                    cantidad: product.cantidad,
                    marca: product.marca,
                    categoria: product.categoria,
                    demografia: product.demografia,
                    imagen: product.imagen
                });
                await nuevoProducto.save();
                contador++;
            } catch (error) {
                console.error(`Error al guardar producto con id ${product.id}: ${error.message}`);
            }
        }

        console.log(`Se cargaron ${contador} datos a Atlas.`);
    } catch (error) {
        console.error('Error al leer el archivo JSON:', error);
    }
};

cargarAtlas();