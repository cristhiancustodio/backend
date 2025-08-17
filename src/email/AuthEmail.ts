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
}