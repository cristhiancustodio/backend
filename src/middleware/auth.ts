
import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { prisma } from '../lib/prisma'
import type { User } from '../Types/User'

declare global {
    namespace Express {
        interface Request {
            user?: User["usuario"]
        }
    }
}

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
    const bearer = req.headers.authorization
    if (!bearer) {
        const error = new Error('No Autorizado')
        return res.status(401).json({ error: error.message })
    }

    const [, token] = bearer.split(' ')

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        if (typeof decoded === 'object' && decoded.userId) {
            const user = await prisma.usuarios.findUnique({
                where: { id: decoded.userId },
                select: { id: true, name: true, apellido: true },
            });
            if (user) {
                req.user = user.name
                next()
            } else {
                res.status(500).json({ error: 'Token No Válido' })
            }
        } else {
            return res.status(500).json({ error: 'Token No Válido' })
        }
    } catch (error) {
        res.status(500).json({ error: 'Token No Válido' })
    }

}
