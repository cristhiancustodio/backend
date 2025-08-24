import { transporter } from "../config/nodemailer";

export class AuthEmail {
    static sendConfirmationEmail = async (data: { email: string, name: string, code: string }) => {
        const info = await transporter.sendMail({
            from: 'cryisthian_06@hotmail.com',
            to: data.email,
            subject: 'Correo de prueba',
            text: 'Este es un correo de prueba',
            html: `<b>Hola ${data.name}, este es un correo de prueba codigo: ${data.code}</b>`,
        });

        console.log("Confirmation email sent:", info.messageId);
    }


    static sendResetPasswordEmail = async (data: { email: string, name: string, code: string }) => {
        const info = await transporter.sendMail({
            from: 'cryisthian_06@hotmail.com',
            to: data.email,
            subject: 'Restablecer contraseña',
            text: 'Este es un correo para restablecer tu contraseña',
            html: `<b>Hola ${data.name}</b>.<br>Este es un correo para restablecer tu contraseña. Ingresa a este enlace para restear la contraseña: <a href="${process.env.FRONTEND_URL}/reset-password?token=${data.code}">Restablecer contraseña</a>`,
        });

        console.log("Reset password email sent:", info.messageId);
    }
}