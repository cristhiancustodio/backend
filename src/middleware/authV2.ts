/**
 * 
 * ESTA AUTENTICACION ES CON LOS USUARIOS DE AWS COGNITO
 */


import { Request, Response, NextFunction } from "express";
import jwt, { JwtHeader } from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { User } from "../Types/User";

declare global {
    namespace Express {
        interface Request {
            user?: {
                id?: User["id"],
                username?: User["usuario"],
                email?: String
            }
        }
    }
}

const region = process.env.AWS_COGNITO_REGION as string;
const userPoolId = process.env.AWS_COGNITO_USERPOOL_ID as string;
const clientId = process.env.AWS_COGNITO_CLIENT_ID as string;

const client = jwksClient({
    jwksUri: `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`
});

function getKey(header: JwtHeader, callback: jwt.SigningKeyCallback) {
    client.getSigningKey(header.kid as string, function (err, anyKey) {
        if (err) {
            callback(err, undefined);
            return;
        }
        const key = anyKey.getPublicKey();
        callback(null, key);
    });
}

export const authenticate = (req: Request, res: Response, next: NextFunction) => {
    const bearer = req.headers.authorization;

    if (!bearer) {
        return res.status(401).json({ error: "No autorizado. Token requerido." });
    }

    const [, token] = bearer.split(" ");
    try {

        return jwt.verify(
            token,
            getKey,
            {
                audience: clientId,
                issuer: `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
            },
            (err, decoded: any) => {

                console.log("decode: ", decoded, err);

                if (err || !decoded) {
                    return res.status(401).json({ error: "Token inválido" });
                }

                req.user = {
                    id: decoded.sub,
                    username: decoded["cognito:username"],
                    email: decoded.email
                };
                return next();
            }
        );


    } catch (error) {

    }
};
