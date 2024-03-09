import '../../connection.js'; // Importa el archivo de conexión
import Product from '../model/producto.model.js'; // Importa el modelo Product

const cargarUnoAtlas = async (producto) => {
    const intentosMaximos = 3; // Número máximo de intentos permitidos
    let contadorIntentos = 0;
    
    while (contadorIntentos < intentosMaximos) {
        let nuevoId = Math.floor(Math.random() * 1000); // Genera un nuevo id al azar
        try {
            const nuevoProducto = new Product({
                id: nuevoId,
                titulo: producto.titulo,
                descripcion: producto.descripcion,
                code: producto.code,
                precio: producto.precio,
                estado: producto.estado,
                cantidad: producto.cantidad,
                marca: producto.marca,
                categoria: producto.categoria,
                demografia: producto.demografia,
                imagen: producto.imagen
            });
            await nuevoProducto.save();
            console.log(`Producto con id ${nuevoId} cargado a Atlas.`);
            break; // Salir del bucle si se guardó correctamente
        } catch (error) {
            if (error.code === 11000 && error.message.includes("id")) {
                console.error(`Error al cargar el producto con id ${nuevoId}: ${error.message}`);
            } else {
                console.error(`Error al cargar el producto con id ${nuevoId}: ${error.message}`);
                break; // Salir del bucle en caso de otro tipo de error
            }
        }
        contadorIntentos++;
    }

    if (contadorIntentos === intentosMaximos) {
        console.error(`Se alcanzó el número máximo de intentos (${intentosMaximos}) sin poder cargar el producto.`);
    }
};

// Uso de la función cargarUnoAtlas
const producto = {
    titulo: "Producto de ejemplo",
    descripcion: "Descripción del producto",
    code: "aaa001",
    precio: 100,
    estado: true,
    cantidad: 10,
    marca: "Marca",
    categoria: "Categoria",
    demografia: "u",
    imagen: "imagen.jpg"
};

cargarUnoAtlas(producto);