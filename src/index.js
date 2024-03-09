import express from "express";
import { engine } from "express-handlebars";
import { __dirname } from "./utils.js";
import * as path from "path";
import cookieParser from "cookie-parser";
import session from "express-session";
import "./connection.js";
import Product from './dao/model/producto.model.js'; // Importa el modelo Product
import Carts from './dao/model/cart.model.js'; // Importa el modelo Cart
import Users from './dao/model/user.model.js'; // Importa el modelo User
import bcrypt from 'bcryptjs';
import passport from "passport";
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GitHubStrategy } from 'passport-github2';

const GITHUB_CLIENT_ID = 'f9d64b4d44b659c69bdd';
const GITHUB_CLIENT_SECRET = '695b52effddebe0be38b95e3d495eeb258e26230';



//Configuraciones

const app = express();
const PORT = 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('tu_secreto')); //
app.use(session({
  secret: 'tu_secreto', // Cambia esto por una cadena de caracteres segura
  resave: true, //
  saveUninitialized: true
}));

app.use(passport.initialize());//
app.use(passport.session());//

app.listen(PORT, () => { console.log(`Server run Express port: ${PORT}`); });

app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", path.resolve(__dirname + "/views"));
app.use("/", express.static(__dirname + "/public"));

const admin = {
  name: 'Admin',
  lastName: 'Admin',
  email: 'adminCoder@coder.com',
  rol: 'admin'
};

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
  try {
    // Verificar si las credenciales corresponden al administrador
    if (email === "adminCoder@coder.com" && password === "adminCod3r123") {
      const admin = {
        _id: 1,
        name: 'Admin',
        lastName: 'Admin',
        email: 'adminCoder@coder.com',
        rol: 'admin'
      };
      return done(null, admin);
    }

    // Buscar al usuario en la base de datos por su correo electrónico
    const usuario = await Users.findOne({ email });

    if (!usuario) {
      // Si el usuario no existe, devolver un error
      return done(null, false, { message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña del usuario utilizando bcrypt
    const isPasswordValid = await bcrypt.compare(password, usuario.password);

    if (isPasswordValid) {
      // Si la contraseña es válida, devolver el usuario
      return done(null, usuario);
    } else {
      // Si la contraseña no es válida, devolver un mensaje de error
      return done(null, false, { message: 'Contraseña incorrecta' });
    }
  } catch (error) {
    // Si ocurre un error, devolver el error
    return done(error);
  }
}));

passport.serializeUser((usuario, done) => {
  // Serializa el usuario para almacenarlo en la sesión
  done(null, usuario._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    if (id === 1) {
      // Si el ID es 1, devolver el usuario administrador
      const admin = {
        _id: 1,
        name: 'Admin',
        lastName: 'Admin',
        email: 'adminCoder@coder.com',
        rol: 'admin'
      };
      return done(null, admin);
    }

    // De lo contrario, buscar al usuario en la base de datos
    const usuario = await Users.findById(id);
    done(null, usuario);
  } catch (error) {
    done(error);
  }
});


// Middleware de Passport para inicializar y manejar las sesiones
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:8080/auth/github/callback"
},
async (accessToken, refreshToken, profile, done) => {
  // Aquí puedes manejar la autenticación de usuario
  console.log(profile._json.email)
  const email = profile._json.email;
  
  // Buscar al usuario en la base de datos por su correo electrónico
  const usuario = await Users.findOne({ email });

  console.log(usuario)

  if (!usuario) {
    // Si el usuario no existe, devolver un error
    return done(null, false, { message: 'Usuario no encontrado' });
  }

  return done(null, usuario);
}
));

// Middleware para verificar si el usuario está autenticado
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next(); // Si el usuario está autenticado, continuar con la siguiente función de middleware
  }
  res.redirect('/log'); // Si el usuario no está autenticado, redirigir al login
};

// Ruta inicial para iniciar la autenticación con GitHub
app.get('/auth/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

// Ruta de callback para GitHub
app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/log' }),
  function(req, res) {
    // Autenticación exitosa, redirige a la página principal o a donde lo necesites
    res.redirect('/');
  }
);


app.get('/', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.passport.user;
    const page = parseInt(req.query.page) || 1; // Página actual, si no se proporciona, será la primera página
    const limit = parseInt(req.query.limit) || 10; // Cantidad de productos por página, por defecto 10
    const marca = req.query.marca || ''; // Marca para filtrar, si no se proporciona, será una cadena vacía
    const orden = req.query.orden || 'asc'; // Orden por precio, si no se proporciona, será ascendente
    const result = await searchProducts(page, limit, marca, orden);
    let user; // Declaración de la variable user fuera del bloque if

    console.log(userId)

    if (userId != 1) {
      user = await searchUserPorId(userId);
    } else {
      user = admin;
    }

    console.log(user)

    res.render("home", { title: "Home handelbars", productos: result.productos, pagination: result.pagination, marca: marca, orden: orden, user: user }); // Renderiza la plantilla con los productos, la información de paginación, la marca y la orden para mostrarla en la plantilla
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});


// Ruta para registrar un usuario
app.get("/log", (req, res) => {
  res.render("log", { title: "log" });
});

// Ruta para registrar un usuario
app.post("/register", async (req, res, next) => {
  try {
    const { name, lastName, email, password } = req.body;

    // Hash del password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear un nuevo usuario
    const nuevoUsuario = new Users({
      name,
      lastName,
      email,
      password: hashedPassword // Usar el password hasheado
    });

    // Guardar el usuario en la base de datos
    await nuevoUsuario.save();

    // Autenticar al usuario recién registrado
    passport.authenticate('local', {
      successRedirect: '/',
      failureRedirect: '/log',
    })(req, res, next);
  } catch (error) {
    console.error("Error al crear el usuario:", error.message);
    res.redirect("/log");
  }
});

// Ruta para iniciar sesión
app.post("/login", passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/log',
}));

// Ruta para cerrar sesión
app.post("/logout", (req, res) => {
  // Destruye la sesión, eliminando el usuario de la sesión
  req.session.destroy();
  res.send("Sesión cerrada correctamente");
});


//Rutas

// Ruta para ver un solo producto
app.get('/productos/:id', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const idProducto = parseInt(req.params.id, 10);
    const producto = await searchProductsPorId2(idProducto);
    console.log(producto)

    if (!producto) {
      res.status(404).send(`No se encontró un producto con id ${idProducto}.`);
      return;
    }
    let user; // Declaración de la variable user fuera del bloque if

    if (userId != 1) {
      user = await searchUserPorId(userId);
    } else {
      user = admin;
    }
    res.render("producto", { title: 'Producto', producto: producto, user: user });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para borrar un producto por ID
app.delete('/productos/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const deletedProduct = await Product.findByIdAndDelete(id);
    if (!deletedProduct) {
      return res.status(404).send("Producto no encontrado");
    }
    res.status(200).send("Producto eliminado correctamente");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para borrar todos lo productos de un carrito 
app.delete('/carts/:id', async (req, res) => {
  try {
    const idCarrito = parseInt(req.params.id, 10);

    await deleteAllProductosPorId(idCarrito);

    // Ejemplo de mensaje de éxito
    res.status(200).send(`Todos los productos del carrito con id ${idCarrito} han sido eliminados.`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para borrar un producto del carrito por ID
app.delete('/carts/:idCarrito/productos/:idProducto', async (req, res) => {
  try {
    const idC = parseInt(req.params.idCarrito, 10);
    const idP = parseInt(req.params.idProducto, 10);
    await deleteProductoDelCarritoPorId(idC, idP);
    res.status(200).send(`Producto con id ${idP} eliminado del carrito con id ${idC}.`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para crear un nuevo carrito
app.post("/carts", async (req, res) => {
  try {
    const nuevoCarritoId = await crearCarrito();
    res.status(201).json({ id: nuevoCarritoId });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para agregar un producto al carrito
app.post("/carts/:idCarrito/productos/:idProducto", async (req, res) => {
  try {
    const idCarrito = parseInt(req.params.idCarrito, 10);
    const idProducto = parseInt(req.params.idProducto, 10);
    await cargarCarrito(idCarrito, idProducto);
    res.status(200).send(`Producto con id ${idProducto} agregado al carrito con id ${idCarrito}.`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta para mostrar un carrito
app.get('/carts/:id', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const marca = req.query.marca || ''; // Marca para filtrar, si no se proporciona, será una cadena vacía
    const orden = req.query.orden || 'asc'; // Orden por precio, si no se proporciona, será ascendente
    const id = req.params.id;
    const carrito = await searchCartsPorId(id);
    if (!carrito) {
      return res.status(404).send("Carrito no encontrado");
    }
    const productosEnCarrito = [];
    for (const idProducto of carrito.ids) {
      const producto = await searchProductsPorId(idProducto, marca, orden);
      if (producto) {
        productosEnCarrito.push(producto[0]);
      }
    }
    let user; // Declaración de la variable user fuera del bloque if

    if (userId != 1) {
      user = await searchUserPorId(userId);
    } else {
      user = admin;
    }
    console.log(productosEnCarrito)
    res.render("cart", { title: "Carrito de Compras", carrito: productosEnCarrito, marca: marca, orden: orden, user: user });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});


app.put('/api/carts/:cid/products/:pid', async (req, res) => {
  try {
    const { cid, pid } = req.params;
    const { cantidad } = req.body;

    // Validar que la cantidad sea un número positivo
    if (!cantidad || isNaN(cantidad) || cantidad <= 0) {
      return res.status(400).json({ error: 'La cantidad debe ser un número positivo.' });
    }

    // Obtener el carrito por su id
    let carrito = await Carts.findOne({ id: cid });
    if (!carrito) {
      return res.status(404).json({ error: `No se encontró un carrito con id ${cid}.` });
    }

    // Verificar si el producto está en el carrito
    const productoEnCarrito = carrito.products.find(prod => prod.id === pid);
    if (!productoEnCarrito) {
      return res.status(404).json({ error: `El producto con id ${pid} no está en el carrito.` });
    }

    // Actualizar la cantidad del producto en el carrito
    productoEnCarrito.cantidad = cantidad;
    await carrito.save();

    return res.status(200).json({ message: `Cantidad del producto con id ${pid} actualizada en el carrito con id ${cid}.` });
  } catch (error) {
    console.error(`Error al actualizar la cantidad del producto en el carrito: ${error.message}`);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

//Funciones

const searchProducts = async (page = 1, limit = 10, marca = '', orden = 'asc') => {
  const skip = (page - 1) * limit;
  let query = {};
  if (marca) {
    query.marca = marca; // Filtrar por marca si se proporciona
  }

  let sort = { precio: orden === 'asc' ? 1 : -1 }; // Ordenar por precio de forma ascendente o descendente

  const totalProducts = await Product.countDocuments(query);
  const totalPages = Math.ceil(totalProducts / limit);

  const products = await Product.find(query).sort(sort).skip(skip).limit(limit);

  // Convertir los productos a un array de JavaScript
  const productosJS = products.map(product => {
    return {
      _id: product._id,
      code: product.code,
      estado: product.estado,
      cantidad: product.cantidad,
      categoria: product.categoria,
      id: product.id,
      titulo: product.titulo,
      descripcion: product.descripcion,
      marca: product.marca,
      precio: product.precio,
      demografia: product.demografia,
      imagen: product.imagen,
    };
  });

  return {
    productos: productosJS,
    pagination: {
      totalProducts: totalProducts,
      totalPages: totalPages,
      currentPage: page,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1,
      nextPage: page + 1,
      prevPage: page - 1,
    }
  };
};

const searchProductsPorId = async (idProducto, marca = '', orden = 'asc') => {
  try {
    let filtro = { id: idProducto };
    if (marca) {
      filtro.marca = marca;
    }

    const productos = await Product.find(filtro).sort({ precio: orden });
    if (!productos.length) {
      console.error(`No se encontró ningún producto con id ${idProducto}.`);
      return null;
    }

    console.log("Productos encontrados:");

    // Convertir los productos a un array de objetos JavaScript
    const productosJS = productos.map(producto => {
      return {
        id: producto.id,
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
      };
    });

    return productosJS;
  } catch (error) {
    console.error(`Error al buscar los productos: ${error.message}`);
    return null;
  }
};

const searchProductsPorId2 = async (idProducto) => {
  try {
    const producto = await Product.findOne({ id: idProducto });
    if (!producto) {
      console.error(`No se encontró un producto con id ${idProducto}.`);
      return null;
    }

    console.log("Producto encontrado:");

    // Convertir el producto a un objeto JavaScript
    const productoJS = {
      id: producto.id,
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
    };

    return productoJS;
  } catch (error) {
    console.error(`Error al buscar el producto: ${error.message}`);
    return null;
  }
};

const searchCartsPorId = async (idCarrito) => {
  try {
    const carrito = await Carts.findOne({ id: idCarrito });
    if (!carrito) {
      console.error(`No se encontró un carrito con id ${idCarrito}.`);
      return null;
    }

    console.log("Carrito encontrado:");
    console.log(carrito);

    // Convertir el carrito a un objeto JavaScript
    const carritoJS = {
      id: carrito.id,
      ids: carrito.products.map(producto => producto.id)
    };

    return carritoJS;
  } catch (error) {
    console.error(`Error al buscar el carrito: ${error.message}`);
    return null;
  }
};

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

const deleteProductoDelCarritoPorId = async (idCarrito, idProducto) => {
  try {
    // Obtener el carrito por su id
    const carrito = await Carts.findOne({ id: idCarrito });
    if (!carrito) {
      console.error(`No se encontró un carrito con id ${idCarrito}.`);
      return;
    }

    // Eliminar el producto del carrito por su id
    carrito.products = carrito.products.filter(prod => prod.id !== idProducto);
    // Guardar el carrito actualizado en la base de datos
    await carrito.save();
    console.log(`Producto con id ${idProducto} eliminado del carrito con id ${idCarrito}.`);
  } catch (error) {
    console.error(`Error al eliminar el producto del carrito: ${error.message}`);
  }
};

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

const deleteAllProductosPorId = async (idCarrito) => {
  try {
    // Buscar el carrito por su ID
    const carrito = await Carts.findOne({ id: idCarrito });
    if (!carrito) {
      console.error(`No se encontró un carrito con id ${idCarrito}.`);
      return;
    }

    // Eliminar todos los productos del array 'products' del carrito
    carrito.products = [];
    await carrito.save();

    console.log(`Todos los productos del carrito con id ${idCarrito} han sido eliminados.`);
  } catch (error) {
    console.error(`Error al eliminar los productos del carrito: ${error.message}`);
  }
};

const searchUserPorId = async (idUser) => {
  try {
    const user = await Users.findOne({ _id: idUser });
    if (!user) {
      console.error(`No se encontró un usuario con id ${idUser}.`);
      return null;
    }

    // Convertir el usuario a un objeto JavaScript
    const userJS = {
      name: user.name,
      lastName: user.lastName,
      email: user.email,
      rol: user.rol
    };

    return userJS;
  } catch (error) {
    console.error(`Error al buscar el usuario: ${error.message}`);
    return null;
  }
};

const userValidation = async (email, password) => {
  try {
    const usuario = await Users.findOne({ email, password });
    if (usuario) {
      return usuario._id;
    }
    return null;
  } catch (error) {
    console.error(`Error al buscar usuario: ${error.message}`);
    return null;
  }
};