import { Router } from 'express'
import type { Request, Response } from 'express'
import { body, param } from 'express-validator'
import { authenticate } from '../middleware/auth'
import { generateJWT, JwtPayload, signJwt } from '../utils/jwt'
import { hashPassword } from '../utils/auth'
import jwt from 'jsonwebtoken'
import { randomUUID } from 'crypto'
import { AuthEmail } from '../email/AuthEmail'

const authRoutes = Router()

// authRoutes.use(authenticate);
type Client = {
    id: string;
    name: string;
    email: string;
    user: string;
    password: string;
    confirmed: boolean;
}

const client: Client = {
    id: 'cc-73037294',
    name: 'Cristhian',
    email: 'cristhian@example.com',
    user: 'ccustodio',
    password: 'mi_contraseña_secreta',
    confirmed: false,
}

const confirmedEmail = (email: Client['email'], user: Client['user']) => {
    AuthEmail.sendConfirmationEmail({
        email: email,
        name: user
    })
}

authRoutes.post("/sendEmail", (req: Request, res: Response) => {
    try {
        const { email, user } = req.body;
        confirmedEmail(email, user);
        return res.status(200).json({
            error: false,
            code: 200,
            message: 'Confirmation email sent'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            code: 500,
            message: error.message
        });
    }
});

authRoutes.post("/register", (req: Request, res: Response) => {
    try {
        const { email, user, password } = req.body;
        if (!email.trim() || !user.trim() || !password.trim()) {
            throw new Error("Faltan datos");
        }

        const hashedPassword = hashPassword(password);
        confirmedEmail(email, user);

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
})
authRoutes.post('/confirmed', (req: Request, res: Response) => {
    try {
        const { code } = req.body;
        if (!code || code !== '123456') {
            throw new Error("Código no valido");
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
        if (user === client.user && password === client.password) {

            
            if (client.confirmed === false) {

                return res.status(401).json({
                    message: 'La cuenta aun no ha sido confirmada, por favor verifica tu correo electrónico.'
                });

            }

            //return res.json(client);
            const sessionId = randomUUID();
            // Generar JWT de acceso
            accessToken = signJwt({
                userId: client.id,
                email: client.email,
                type: 'access',
            }, {
                ttl: '3m',
                subject: client.id,
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
                subject: client.id,
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
        } else {
            throw new Error("Credenciales no correctas");
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
        const refreshToken = req.cookies?.refresh_token;
        console.log(req.cookies);

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
            ttl: '10m',
            subject: payload.userId,
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

authRoutes.post('/logout', (req: Request, res: Response) => {
    try {
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