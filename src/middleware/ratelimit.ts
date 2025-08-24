/*import rateLimit from 'express-rate-limit';

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
});*/