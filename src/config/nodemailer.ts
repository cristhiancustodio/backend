import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config()

const config = () => {
    return {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        // secure: process.env.SMTP_SECURE === 'true',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        },
        // tls: {
        //     rejectUnauthorized: false
        // }
    };
}

export const transporter = nodemailer.createTransport(config());