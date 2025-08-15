// import mongoose from 'mongoose'
import { exit } from 'node:process';

export const connectDB = async () => {
    try {
        // const {connection} = await mongoose.connect(process.env.DATABASE_URL)
        // const url = `${connection.host}:${connection.port}`
        // console.log(`MongoDB Conectado en: ${url}`);
    } catch (error) {
        // console.log(error.message)
        console.log('Error al conectar a MongoDB', error.message);
        exit(1)
    }
}