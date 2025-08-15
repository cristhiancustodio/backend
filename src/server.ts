import express from 'express'
import dotenv from 'dotenv'
import cors from 'cors'
import morgan from 'morgan'
import authRoutes from './routes/authRoutes'
import { corsConfig } from './config/cors'
import helmet from 'helmet'
import userRoutes from './routes/userRoutes'
import cookieParser from 'cookie-parser'
// import { connectDB } from './config/db'


dotenv.config()
// connectDB()

const app = express()

// Seguridad HTTP básica
app.use(helmet());
app.use(cors(corsConfig))
// Leer datos de formularios
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
// app.use(pinoHttp());
// Logging
app.use(morgan('dev'))



// Routes
app.use('/api/user', userRoutes)
app.use('/api/auth', authRoutes)

export default app