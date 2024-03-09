import '../../connection.js'; // Importa el archivo de conexión
import Message from '../model/message.model.js'; // Importa el modelo Message

const searchMessages = async () => {
    try {
        // Busca todos los mensajes en la base de datos
        const messages = await Message.find();
        console.log(messages)
        return messages;
    } catch (error) {
        console.error(error);
        throw new Error('Error al obtener los mensajes');
    }
};

searchMessages();