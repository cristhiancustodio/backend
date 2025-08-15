# 📁 Estructura de archivos(monorepo en un documento)

A continuación tienes un proyecto Express completo, listo para pegar en tu editor.Cada sección está marcada con el nombre del archivo.Copia cada bloque en su respectivo archivo.

---

// file: package.json
{
    "name": "express-auth-starter",
    "version": "1.0.0",
    "type": "module",
    "main": "src/index.js",
    "scripts": {
        "dev": "node --env-file=.env src/index.js",
        "start": "node src/index.js"
    },
    "dependencies": {
        "argon2": "^0.40.1",
        "cookie-parser": "^1.4.6",
        "cors": "^2.8.5",
        "dotenv": "^16.4.5",
        "express": "^4.19.2",
        "express-rate-limit": "^7.4.0",
        "helmet": "^7.1.0",
        "jose": "^5.8.0",
        "pino-http": "^10.3.0"
    }
}

---

// file: .env.example
# Claves JWT — usa RS256 en prod.Para pruebas rápidas, puedes usar HS256.
# Opción RS256(recomendada):
# JWT_ALG = RS256
# JWT_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
# JWT_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"

# Opción HS256(solo dev):
JWT_ALG = HS256
JWT_SECRET = super- secreto - cambiar

# Tiempos de vida(ejemplos)
ACCESS_TOKEN_TTL = 15m
REFRESH_TOKEN_TTL = 30d

# Cookies
COOKIE_DOMAIN = localhost
COOKIE_SECURE = false
COOKIE_SAMESITE = Lax

# App
PORT = 3000
CORS_ORIGINS = http://localhost:5173,http://localhost:3000

---

// file: src/index.js
import './load-env.js';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pinoHttp from 'pino-http';
import { rateLimiterLogin, rateLimiterRefresh } from './middlewares/rateLimit.js';
import authRouter from './routes/auth.js';
import protectedRouter from './routes/protected.js';

const app = express();

// Seguridad HTTP básica
app.use(helmet());

// CORS estricto: lee orígenes desde env
const allowList = (process.env.CORS_ORIGINS || '').split(',').filter(Boolean);
app.use(
    cors({
        origin: function (origin, cb) {
            if (!origin) return cb(null, true); // permitir herramientas como curl/postman
            return cb(null, allowList.includes(origin));
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
    })
);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(pinoHttp());

// Rate limit específico para rutas sensibles
app.use('/auth/login', rateLimiterLogin);
app.use('/auth/refresh', rateLimiterRefresh);

// Rutas
app.use('/auth', authRouter);
app.use('/api', protectedRouter);

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
    console.log(`✅ API escuchando en http://localhost:${port}`);
});

---

// file: src/load-env.js
import dotenv from 'dotenv';
dotenv.config();

---

// file: src/config.js
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

---

// file: src/utils/crypto.js
import * as argon2 from 'argon2';

export async function hash(value) {
    return argon2.hash(value);
}

export async function verify(hashValue, plain) {
    return argon2.verify(hashValue, plain);
}

---

// file: src/utils/jwt.js
import { SignJWT, jwtVerify } from 'jose';
import { createSecretKey } from 'crypto';
import ms from 'ms';
import { config } from '../config.js';

function getSigningKey() {
    const { alg, secret, privateKey } = config.jwt;
    if (alg === 'HS256') {
        if (!secret) throw new Error('JWT_SECRET requerido para HS256');
        return createSecretKey(Buffer.from(secret));
    }
    if (!privateKey) throw new Error('JWT_PRIVATE_KEY requerido para RS256');
    return privateKey;
}

function getVerifyKey() {
    const { alg, secret, publicKey } = config.jwt;
    if (alg === 'HS256') {
        if (!secret) throw new Error('JWT_SECRET requerido para HS256');
        return createSecretKey(Buffer.from(secret));
    }
    if (!publicKey) throw new Error('JWT_PUBLIC_KEY requerido para RS256');
    return publicKey;
}

export async function signJwt(payload, { ttl, subject, sessionId, audience }) {
    const key = getSigningKey();
    const { alg } = config.jwt;

    const now = Math.floor(Date.now() / 1000);
    let jwt = new SignJWT({ ...payload, sid: sessionId })
        .setProtectedHeader({ alg, typ: 'JWT' })
        .setIssuedAt(now)
        .setSubject(String(subject))
        .setIssuer('auth.example')
        .setAudience(audience || 'api')
        .setExpirationTime(ttl || config.jwt.accessTtl);

    return await jwt.sign(key);
}

export async function verifyJwt(token) {
    const key = getVerifyKey();
    const { payload } = await jwtVerify(token, key, {
        issuer: 'auth.example',
        audience: 'api'
    });
    return payload;
}

---

// file: src/services/sessionStore.js
/**
 * Implementación in-memory para demo. En producción, usa BD: Postgres, Redis, etc.
 * Guardamos el hash del RT vigente por sesión.
 */
const sessions = new Map(); // sid -> { userId, rtHash, status, createdAt, lastUsedAt }

export const SessionStatus = {
    ACTIVE: 'active',
    REVOKED: 'revoked',
    COMPROMISED: 'compromised',
};

export function createSession({ sid, userId, rtHash }) {
    const now = new Date();
    sessions.set(sid, { userId, rtHash, status: SessionStatus.ACTIVE, createdAt: now, lastUsedAt: now });
}

export function getSession(sid) {
    return sessions.get(sid);
}

export function updateSession(sid, patch) {
    const current = sessions.get(sid);
    if (!current) return;
    sessions.set(sid, { ...current, ...patch, lastUsedAt: new Date() });
}

export function revokeSession(sid) {
    const current = sessions.get(sid);
    if (!current) return;
    current.status = SessionStatus.REVOKED;
    sessions.set(sid, current);
}

export function markCompromised(sid) {
    const current = sessions.get(sid);
    if (!current) return;
    current.status = SessionStatus.COMPROMISED;
    sessions.set(sid, current);
}

---

// file: src/middlewares/rateLimit.js
import rateLimit from 'express-rate-limit';

export const rateLimiterLogin = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts, please try later.' }
});

export const rateLimiterRefresh = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
});

---

// file: src/middlewares/requireAuth.js
import { verifyJwt } from '../utils/jwt.js';
import { getSession, SessionStatus } from '../services/sessionStore.js';

export async function requireAuth(req, res, next) {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Missing access token' });

        const payload = await verifyJwt(token);
        const sid = payload.sid;
        if (!sid) return res.status(401).json({ error: 'Invalid token (no sid)' });

        const session = getSession(sid);
        if (!session || session.status !== SessionStatus.ACTIVE) {
            return res.status(401).json({ error: 'Session not active' });
        }

        req.user = { id: payload.sub, sid, scope: payload.scope, role: payload.role };
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

---

// file: src/routes/auth.js
import { Router } from 'express';
import { randomUUID } from 'crypto';
import { signJwt, verifyJwt } from '../utils/jwt.js';
import { hash, verify as verifyHash } from '../utils/crypto.js';
import {
    createSession,
    getSession,
    updateSession,
    revokeSession,
    markCompromised,
    SessionStatus
} from '../services/sessionStore.js';
import { config } from '../config.js';

const router = Router();

// Utilidad: setear cookie de refresh segura
function setRefreshCookie(res, token) {
    const opts = {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        domain: config.cookie.domain || undefined,
        path: '/auth/refresh',
    };
    // Asignar Max-Age según TTL (no parseamos exacto aquí; navegadores aceptan sin Max-Age también)
    res.cookie('refresh_token', token, opts);
}

function clearRefreshCookie(res) {
    res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        domain: config.cookie.domain || undefined,
        path: '/auth/refresh',
    });
}

// MOCK de usuarios (reemplaza con BD real)
const users = [
    // password: "password123" (no guardes planos en prod)
    { id: '1', email: 'user@example.com', passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$4F9f2B7j1kJ7Q8m3Wg$obviously-replace-in-prod' }
];

router.post('/login', async (req, res) => {
    const { email, password } = req.body || {};
    // Valida inputs
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    // Para demo omitimos verificar argon2 real
    // const ok = await argon2.verify(user.passwordHash, password)
    const ok = password === 'password123';
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const sid = randomUUID();
    const accessToken = await signJwt({ role: 'user' }, {
        ttl: config.jwt.accessTtl,
        subject: user.id,
        sessionId: sid,
        audience: 'api'
    });

    const refreshToken = await signJwt({ type: 'refresh' }, {
        ttl: config.jwt.refreshTtl,
        subject: user.id,
        sessionId: sid,
        audience: 'auth'
    });

    const rtHash = await hash(refreshToken);
    createSession({ sid, userId: user.id, rtHash });

    setRefreshCookie(res, refreshToken);
    return res.json({ accessToken, user: { id: user.id, email: user.email } });
});

router.post('/refresh', async (req, res) => {
    try {
        const rt = req.cookies?.refresh_token;
        if (!rt) return res.status(401).json({ error: 'Missing refresh token' });

        const payload = await verifyJwt(rt);
        if (payload.type !== 'refresh') return res.status(401).json({ error: 'Not a refresh token' });

        const sid = payload.sid;
        const session = getSession(sid);
        if (!session || session.status !== SessionStatus.ACTIVE) {
            return res.status(401).json({ error: 'Session inactive' });
        }

        const valid = await verifyHash(session.rtHash, rt);
        if (!valid) {
            // Reutilización / robo detectado
            markCompromised(sid);
            clearRefreshCookie(res);
            return res.status(401).json({ error: 'Refresh token reuse detected' });
        }

        // Rotación
        const newAccess = await signJwt({ role: 'user' }, {
            ttl: config.jwt.accessTtl,
            subject: payload.sub,
            sessionId: sid,
            audience: 'api'
        });

        const newRefresh = await signJwt({ type: 'refresh' }, {
            ttl: config.jwt.refreshTtl,
            subject: payload.sub,
            sessionId: sid,
            audience: 'auth'
        });

        const newRtHash = await hash(newRefresh);
        updateSession(sid, { rtHash: newRtHash });

        setRefreshCookie(res, newRefresh);
        return res.json({ accessToken: newAccess });
    } catch (err) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }
});

router.post('/logout', async (req, res) => {
    const rt = req.cookies?.refresh_token;
    if (rt) {
        try {
            const payload = await verifyJwt(rt);
            revokeSession(payload.sid);
        } catch (e) {
            // ignore
        }
    }
    clearRefreshCookie(res);
    return res.json({ ok: true });
});

router.post('/logout-all', async (req, res) => {
    const rt = req.cookies?.refresh_token;
    if (!rt) {
        clearRefreshCookie(res);
        return res.json({ ok: true });
    }
    try {
        const payload = await verifyJwt(rt);
        revokeSession(payload.sid);
    } catch (e) {
        // ignore
    }
    clearRefreshCookie(res);
    return res.json({ ok: true });
});

export default router;

---

// file: src/routes/protected.js
import { Router } from 'express';
import { requireAuth } from '../middlewares/requireAuth.js';

const router = Router();

router.get('/profile', requireAuth, (req, res) => {
    return res.json({ user: req.user });
});

export default router;
