import '../../connection.js'; // Importa el archivo de conexión
import Message from '../model/message.model.js'; // Importa el modelo Message

const deleteAllMessages = async () => {
    try {
        const result = await Message.deleteMany({});
        console.log(`${result.deletedCount} mensajes eliminados.`);
    } catch (error) {
        console.error('Error al borrar los mensajes:', error);
        throw new Error('Error al borrar los mensajes');
    }
};

// Uso de la función deleteAllMessages
deleteAllMessages();