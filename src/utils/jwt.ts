import jwt from 'jsonwebtoken';
import { User } from '../Types/User';

// ...
type JwtOptions = {
    ttl: any;
    subject: string;
    sessionId: string;
    audience: string;
};
export type JwtPayload = {
    userId: User['id'];
    email: User['email'];
    type: 'access' | 'refresh';
}
export function signJwt(payload: JwtPayload, options: JwtOptions): string {
    // jsonwebtoken acepta expiresIn como string ("15m", "7d") o number (segundos)
    const signOptions: jwt.SignOptions = {
        expiresIn: options.ttl,
        subject: options.subject,
        audience: options.audience,
        issuer: 'auth.local',
    };
    const token = jwt.sign(
        {
            ...payload,
            sid: options.sessionId,
        },
        process.env.JWT_SECRET as string,
        signOptions
    );
    return token;
}

// Compatibilidad con generateJWT anterior
type UserPayload = {
    id: string,
    nombre: string,
    apellido: string,
}
export const generateJWT = (payload: UserPayload) => {
    const token = jwt.sign(payload, process.env.JWT_SECRET as string, {
        expiresIn: '7h'
    })
    return token
}