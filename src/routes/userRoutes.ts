import { Router } from "express";
import type { Request, Response } from 'express'
import { authenticate } from "../middleware/auth";
import { prisma } from "../lib/prisma";
import { getUserById } from "../models/User";


const userRoutes = Router();

userRoutes.use(authenticate);

userRoutes.get('/', async (req: Request, res: Response) => {
    try {
        const users = await prisma.usuarios.findMany();
        return res.status(200).json({
            code: 200,
            error: false,
            message: 'Users route',
            data: users
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: 'Internal server error'
        });
    }
});
userRoutes.get('/:id', async (req: Request, res: Response) => {
    try {
        const id = +req.params.id;
        if (!id) {
            return res.status(400).json({
                error: true,
                message: 'ID is required'
            });
        }
        const data = await getUserById(id);
        if (!data) {
            return res.status(404).json({
                error: true,
                message: 'User not found'
            });
        }
        return res.status(200).json({
            code: 200,
            error: false,
            message: 'User route',
            data
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: 'Internal server error'
        });
    }
});

export default userRoutes;
