import { Router } from 'express'
import type { Request, Response } from 'express'
import { body, param } from 'express-validator'
import { authenticate } from '../middleware/auth'
import { generateJWT, signJwt } from '../utils/jwt'
import { hashPassword } from '../utils/auth'
import jwt from 'jsonwebtoken'
import { randomUUID } from 'crypto'

const authRoutes = Router()

// authRoutes.use(authenticate);

authRoutes.get('/', async (req: Request, res: Response) => {
    try {
        const accessToken = jwt.sign({
            id: 'aasdasd'
        }, process.env.JWT_SECRET, {
            expiresIn: "30m",
        });


        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 1000 * 60 * 15 //15 min
        });


        const refresh_token = jwt.sign({
            id: 'ccustodio',
            nombre: 'Cristhian',
            apellido: 'Custodio',
        }, process.env.JWT_SECRET, {
            expiresIn: "30d",
        });
        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: 'localhost',
            path: '/',

        });
        res.status(200).json({ message: 'Create account route with token in HttpOnly cookie', refresh_token })
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' })
    }
});

authRoutes.get("/token", async (req: Request, res: Response) => {
    try {
        const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNjdXN0b2RpbyIsIm5vbWJyZSI6IkNyaXN0aGlhbiIsImFwZWxsaWRvIjoiQ3VzdG9kaW8iLCJpYXQiOjE3NTUyMjU5MDMsImV4cCI6MTc1NTI1MTEwM30.6tEFWT69n-PUXE3N-WMAOuhC518PXeNVvr6_1cH0a3s";
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.status(200).json({ message: 'Token generated', token, decoded })
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error: error.message })
    }
});
authRoutes.get("/password", async (req: Request, res: Response) => {
    try {
        const newPassword = await hashPassword("mi_nueva_contraseña");

        res.status(200).json({ message: 'Password hashed', newPassword })
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error: error.message })
    }
});
authRoutes.get('/tokenizacion', async (req: Request, res: Response) => {
    try {
        // Simulación de usuario autenticado (ajusta según tu lógica real)
        const user = { id: 'user-123', email: 'usuario@ejemplo.com' };
        const sessionId = randomUUID();

        // Generar access token para enviar en cada peticion
        const accessToken = signJwt({
            userId: user.id,
            email: user.email,
            type: 'access',
        }, {
            ttl: '15m',
            subject: user.id,
            sessionId,
            audience: 'api',
        });

        // Generar refresh token
        const refreshToken = signJwt({
            userId: user.id,
            type: 'refresh',
        }, {
            ttl: '30d',
            subject: user.id,
            sessionId,
            audience: 'auth',
        });

        // Setear cookie segura para refresh token
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: 'localhost',
            path: '/',
        });

        // Devolver access token en el body
        return res.status(200).json({
            accessToken,
            refreshToken,
            user: { id: user.id, email: user.email },
        });
    } catch (error) {
        return res.status(500).json({ message: 'Error generando tokens', error: error.message });
    }
});
export default authRoutes