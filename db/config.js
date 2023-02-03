const  mongoose  = require("mongoose");

const dbConnection = async() => {
    try {
        mongoose.set("strictQuery", false);
        await mongoose.connect(process.env.BD_CNN)

        console.log('DB Online');

    } catch (error) {
        console.log(error);
        throw new Error('Error a la hora de inicializar la base de datos');
    }
}

module.exports = {
    dbConnection
}