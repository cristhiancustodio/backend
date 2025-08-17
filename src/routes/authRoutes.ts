import { Router } from 'express'
import type { Request, Response } from 'express'
import { body, param } from 'express-validator'

import { JwtPayload, signJwt } from '../utils/jwt'
import { checkPassword, hashPassword } from '../utils/auth'
import jwt from 'jsonwebtoken'
import { randomUUID } from 'crypto'
import { AuthEmail } from '../email/AuthEmail'
import { createUser } from '../models/User'
import { PrismaClient, Usuarios } from '@prisma/client'


const prisma = new PrismaClient();
const authRoutes = Router()

// authRoutes.use(authenticate);

const confirmedEmail = async (email: Usuarios['email'], user: Usuarios['usuario'], id: Usuarios['id']) => {
    const code = Math.floor(100000 + Math.random() * 900000) + '';

    await prisma.token.create({
        data: {
            token: code,
            idUsuario: id
        }
    })
    AuthEmail.sendConfirmationEmail({
        email: email,
        name: user,
        code: code
    })
}

authRoutes.post("/newCode", async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        const user = await prisma.usuarios.findFirst({ where: { email } });

        if (!user) {
            return res.status(404).json({
                error: true,
                code: 404,
                message: 'Usuario no encontrado'
            });
        }

        await confirmedEmail(email, user.usuario, user.id);

        return res.status(200).json({
            error: false,
            code: 200,
            message: 'Nuevo codigo enviado'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        });
    }
});

authRoutes.post("/register", async (req: Request, res: Response) => {
    try {
        const { name, apellido, email, usuario, password } = req.body;
        if (!name.trim() || !apellido.trim() || !email.trim() || !usuario.trim() || !password.trim()) {
            throw new Error("Faltan datos");
        }
        const hashedPassword = await hashPassword(password);
        const data = await createUser({ name, apellido, email, usuario, password: hashedPassword });
        if (data) {
            await confirmedEmail(email, usuario, data.id);
        }

        // Aquí iría la lógica para registrar al usuario
        return res.status(201).json({
            error: false,
            code: 201,
            message: 'Usuario registrado, hemos enviado un email de confirmación a tu correo'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        });
    }
});

authRoutes.post('/confirmed', async (req: Request, res: Response) => {
    try {
        const { code } = req.body;
        if (!code.trim()) {
            throw new Error("Falta el código");
        }
        const data = await prisma.token.findFirst({ where: { token: code } });
        if (data) {
            await prisma.usuarios.update({
                where: { id: data.idUsuario }, data: { confirmed: true }
            });
            await prisma.token.delete({ where: { id: data.id } });
        }
        /**Si el codigo es valido, cambiar el estado de tu campo en al base de datos */
        return res.status(200).json({
            message: 'Confirmated email'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        })
    }
});
authRoutes.post('/login', async (req: Request, res: Response) => {
    try {

        const user = req.body.user;
        const password = req.body.password;

        let accessToken = '';

        const client = await prisma.usuarios.findFirst({
            where: { usuario: user },
            select: { id: true, password: true, email: true, confirmed: true },
        });
        if (!client) {
            throw new Error("Usuario no encontrado");
        }
        const validatePassword = await checkPassword(password, client.password);
        if (validatePassword) {
            if (client.confirmed === false) {
                await confirmedEmail(client.email, user, client.id);
                return res.status(401).json({
                    message: 'La cuenta aun no ha sido confirmada, por favor verifica tu correo electrónico.'
                });
            }
            const sessionId = randomUUID();
            // Generar JWT de acceso
            accessToken = signJwt({
                userId: client.id,
                email: client.email,
                type: 'access',
            }, {
                ttl: '15m',
                subject: client.id + '',
                sessionId,
                audience: 'api',
            });

            // Generar refresh token
            const refreshToken = signJwt({
                userId: client.id,
                email: client.email,
                type: 'refresh',
            }, {
                ttl: '30d',
                subject: client.id + '',
                sessionId,
                audience: 'auth',
            });
            await prisma.usuarios.update({
                where: { id: client.id },
                data: { user_token: refreshToken }
            })
            // Setear cookie segura para refresh token
            res.cookie('refresh_token', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                domain: 'localhost',
                path: '/',
            });
        } else {
            throw new Error("Contraseña no correctas");
        }
        return res.status(200).json({
            token: accessToken
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        })
    }
});

authRoutes.post("/refresh", async (req: Request, res: Response) => {
    try {
        const refreshToken = req.cookies?.refresh_token || '';

        //Busco el refresh token en la bd si existe
        const data = await prisma.usuarios.findFirst({
            where: { user_token: refreshToken }
        });
        if (!data) {
            return res.status(401).json({
                error: true,
                code: 401,
                message: 'Invalid refresh token'
            });
        }
        if (!refreshToken) {
            return res.status(401).json({
                error: true,
                code: 401,
                message: 'No refresh token provided'
            });
        }
        const sessionId = randomUUID();
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        if (typeof decoded !== "object" || decoded === null) {
            throw new Error("Token inválido");
        }
        const payload = decoded as JwtPayload;
        const accessToken = signJwt({
            userId: payload.userId,
            email: payload.email,
            type: 'access',
        }, {
            ttl: '15m',
            subject: payload.userId + '',
            sessionId,
            audience: 'api',
        });

        return res.status(200).json({
            accessToken: accessToken
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        });
    }
});

authRoutes.post('/logout', async (req: Request, res: Response) => {
    try {
        const refreshToken = req.cookies?.refresh_token || '';
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        const payload = decoded as JwtPayload;
        await prisma.usuarios.update({
            where: { id: payload.userId },
            data: { user_token: null }
        });
        // Borrar cookie de refresh token
        res.clearCookie('refresh_token');
        return res.status(200).json({
            message: 'Logged out successfully'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        });
    }
});

export default authRoutes