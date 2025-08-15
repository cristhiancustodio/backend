export const config = {
    jwt: {
        alg: process.env.JWT_ALG || 'RS256', // RS256 recomendado
        secret: process.env.JWT_SECRET, // HS256
        privateKey: process.env.JWT_PRIVATE_KEY, // RS256
        publicKey: process.env.JWT_PUBLIC_KEY, // RS256
        accessTtl: process.env.ACCESS_TOKEN_TTL || '15m',
        refreshTtl: process.env.REFRESH_TOKEN_TTL || '30d',
    },
    cookie: {
        domain: process.env.COOKIE_DOMAIN || undefined,
        secure: String(process.env.COOKIE_SECURE) === 'true',
        sameSite: (process.env.COOKIE_SAMESITE || 'Lax'), // 'Lax'|'Strict'|'None'
    }
};