import { PrismaClient } from '@prisma/client';
import type { ICreateUser, IUser, User } from '../Types/User';

const prisma = new PrismaClient();


export const getUserById = async (id: User['id']): Promise<Omit<User, 'password' | 'user_token'> | null> => {
    try {
        const user = await prisma.usuarios.findUnique({ where: { id } });
        if (!user) {
            return null;
        }
        const { password, user_token, ...safeUser } = user;
        return safeUser;
    } catch (error) {
        console.error('Error fetching user by ID:', error);
        throw new Error('Could not retrieve user');
    }
};
export const createUser = async (data: ICreateUser): Promise<IUser> => {
    const user = await prisma.usuarios.create({
        data: { ...data },
        select: { id: true, name: true, apellido: true },
    });
    return user;
};
