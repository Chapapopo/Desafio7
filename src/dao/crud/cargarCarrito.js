import '../../connection.js'; // Importa el archivo de conexión
import Carts from '../model/cart.model.js'; // Importa el modelo Cart
import Product from '../model/producto.model.js'; // Importa el modelo Product

const modificarProductoPorId = async (id, campo, valor) => {
    try {
        if (campo === 'id' || campo === 'code') {
            console.error(`No se puede modificar el campo ${campo}.`);
            return;
        }

        const update = { [campo]: valor };
        const producto = await Product.findOneAndUpdate({ id: id }, update, { new: true });
        if (!producto) {
            console.error(`No se encontró un producto con id ${id}.`);
            return;
        }
        console.log(`Producto con id ${id} modificado correctamente.`);
    } catch (error) {
        console.error(`Error al modificar el producto con id ${id}: ${error.message}`);
    }
};

const modificarCarritoPorId = async (idCar, idPro, campo, nuevoValor) => {
    try {
        // Definir el filtro para encontrar el carrito por su id y el producto por su id en el array de productos
        const filter = { id: idCar, "products.id": idPro };

        // Definir la actualización para modificar el campo del producto
        const update = { $set: { [`products.$.${campo}`]: nuevoValor } };

        // Realizar la actualización
        const carritoActualizado = await Carts.findOneAndUpdate(filter, update, { new: true });

        if (!carritoActualizado) {
            console.error(`No se encontró un carrito con id ${idCar} o un producto con id ${idPro} en el carrito.`);
            return;
        }

        console.log(`Producto con id ${idPro} en el carrito con id ${idCar} actualizado.`);
    } catch (error) {
        console.error(`Error al modificar el producto en el carrito: ${error.message}`);
    }
};

const cargarCarrito = async (idCarrito, idProducto) => {
    try {
        // Obtener el producto por su id
        const producto = await Product.findOne({ id: idProducto });
        if (!producto) {
            console.error(`No se encontró un producto con id ${idProducto}.`);
            return;
        }

        // Verificar que la cantidad del producto sea mayor que cero
        if (producto.cantidad === 0) {
            console.error(`El producto con id ${idProducto} no está disponible.`);
            return;
        }

        // Obtener el carrito por su id
        let carrito = await Carts.findOne({ id: idCarrito });
        if (!carrito) {
            console.error(`No se encontró un carrito con id ${idCarrito}.`);
            return;
        }
        
        // Verificar si el producto ya está en el carrito
        const productoEnCarrito = carrito.products.find(prod => prod.id === idProducto);
        if (productoEnCarrito) {
            // Incrementar la cantidad del producto en el carrito
            await modificarCarritoPorId(idCarrito, idProducto, 'cantidad', productoEnCarrito.cantidad + 1);
            console.log(`Cantidad del producto con id ${idProducto} en el carrito con id ${idCarrito} incrementada.`);
            
            await modificarProductoPorId(idProducto, 'cantidad', producto.cantidad - 1);
            console.log(`Cantidad de producto con id ${idProducto} actualizada.`);
            return;
        }

        // Agregar el producto al carrito
        const update = {
            $push: {
                products: {
                    id: producto.id,
                    titulo: producto.titulo,
                    cantidad: 1
                }
            }
        };
        const productoActualizado = await Carts.findOneAndUpdate({ id: idCarrito }, update, { new: true });
        console.log(`Producto con id ${idProducto} agregado al carrito con id ${idCarrito}.`);

        // Reducir la cantidad disponible en la base de datos
        if (productoActualizado) {
            await modificarProductoPorId(idProducto, 'cantidad', producto.cantidad - 1);
            console.log(`Cantidad de producto con id ${idProducto} actualizada.`);
        }
    } catch (error) {
        console.error(`Error al cargar el producto en el carrito: ${error.message}`);
    }
};

// Uso de la función cargarCarrito
const idCarrito = 552; // ID del carrito al que se quiere agregar el producto
const idProducto = 3; // ID del producto que se quiere agregar
cargarCarrito(idCarrito, idProducto);