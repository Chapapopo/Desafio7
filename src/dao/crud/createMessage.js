import '../../connection.js'; // Importa el archivo de conexión
import Message from '../model/message.model.js'; // Importa el modelo Message

const createMessage = async (userData, messageData) => {
    try {
        const { user } = userData;
        const { message } = messageData;

        // Crea un nuevo mensaje con los datos proporcionados
        const newMessage = new Message({
            user,
            message
        });

        // Guarda el nuevo mensaje en la base de datos
        await newMessage.save();

        return newMessage;
    } catch (error) {
        console.error(error);
        throw new Error('Error al crear el mensaje');
    }
};

const userData = {
    user: 'UsuarioEjemplo'
};
const messageData = {
    message: 'Este es un mensaje de prueba'
};

createMessage(userData,messageData);