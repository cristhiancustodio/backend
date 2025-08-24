import { Usuarios } from "@prisma/client";
import { AuthEmail } from "../email/AuthEmail";
import { prisma } from "../lib/prisma";
import type { Request, Response } from 'express'
import { checkPassword, hashPassword } from "../utils/auth";
import { createUser, getUserById, updatePassword } from "../models/User";
import jwt from 'jsonwebtoken';
import type { User } from "../Types/User";
import { randomUUID } from "crypto";
import { JwtPayload, signJwt } from "../utils/jwt";

const confirmedEmail = async (email: Usuarios['email'], user: Usuarios['usuario'], id: Usuarios['id']) => {
    const code = Math.floor(100000 + Math.random() * 900000) + '';
    await prisma.token.create({
        data: { token: code, idUsuario: id }
    })
    AuthEmail.sendConfirmationEmail({
        email: email,
        name: user,
        code: code
    })
}
export class AuthController {
    static newCode = async (req: Request, res: Response) => {
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
    }
    static register = async (req: Request, res: Response) => {
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
    }
    static changePassword = async (req: Request, res: Response) => {
        try {
            const { newPassword, oldPassword } = req.body;
            const user = await prisma.usuarios.findFirst({ where: { id: req.user.id } });
            if (!user) {
                throw new Error("User not found");
            }
            const validateOldPassword = await checkPassword(oldPassword, user.password);
            if (!validateOldPassword) {
                throw new Error("Incorrect old password");
            }
            await updatePassword(req.user.id, newPassword);
            /**Si el codigo es valido, cambiar el estado de tu campo en al base de datos */
            return res.status(200).json({
                message: 'Password updated'
            });
        } catch (error) {
            return res.status(500).json({
                error: true,
                code: 500,
                message: error.message
            });
        }
    }
    static resetPassword = async (req: Request, res: Response) => {
        try {
            const { newPassword, token } = req.body;
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (typeof decoded !== "object" || decoded === null) {
                throw new Error("Token inválido");
            }
            const payload = decoded as { userId: User["id"] };
            const user = await prisma.usuarios.findFirst({ where: { id: payload.userId } });
            if (!user) {
                return res.status(404).json({
                    error: true,
                    code: 404,
                    message: 'Usuario no encontrado'
                });
            }
            await updatePassword(user.id, newPassword);
            // await resetPasswordEmail(email, user.usuario, user.id);

            return res.status(200).json({
                error: false,
                code: 200,
                message: 'Password updated successfully'
            });
        } catch (error) {
            return res.status(500).json({
                error: true,
                code: 500,
                message: error.message
            });
        }
    }
    static forgotPassword = async (req: Request, res: Response) => {
        try {
            const { email } = req.body;
            const user = await prisma.usuarios.findFirst({ where: { email } });
            if (!user) {
                return res.status(404).json({
                    error: true,
                    code: 404,
                    message: 'User not found'
                });
            }
            // Generate a password reset token
            const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
            // Send email with reset link (pseudo code)
            await AuthEmail.sendResetPasswordEmail({ email, name: user.name, code: resetToken });

            return res.status(200).json({
                message: 'Password reset email sent'
            });
        } catch (error) {
            return res.status(500).json({
                error: true,
                code: 500,
                message: error.message
            });
        }
    }
    static confirmedAccount = async (req: Request, res: Response) => {
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
    }

    static login = async (req: Request, res: Response) => {
        try {
            const email = req.body.email;
            const password = req.body.password;

            let accessToken = '';

            const client = await prisma.usuarios.findFirst({
                where: { email: email },
                select: { id: true, password: true, usuario: true, email: true, confirmed: true },
            });
            if (!client) {
                throw new Error("Usuario no encontrado");
            }
            const validatePassword = await checkPassword(password, client.password);
            if (validatePassword) {
                if (client.confirmed === false) {
                    await confirmedEmail(client.email, client.usuario, client.id);
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
    }
    static refreshToken = async (req: Request, res: Response) => {
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
    }
    static logOut = async (req: Request, res: Response) => {
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
    }

    static getMe = async (req: Request, res: Response) => {
        try {
            const user = await getUserById(req.user.id);
            if (!user) {
                return res.status(404).json({
                    error: true,
                    code: 404,
                    message: 'User not found'
                });
            }
            return res.status(200).json({
                user
            });
        } catch (error) {
            return res.status(500).json({
                error: true,
                code: 500,
                message: error.message
            });
        }
    }
}