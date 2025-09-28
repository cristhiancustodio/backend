// utils/response.ts
import { Response } from "express";

interface SuccessOptions<T = any> {
    status?: number;      // default: 200
    message?: string;     // default: ""
    response?: T;         // default: {}
    [key: string]: any;   // for any additional properties
}

interface ErrorOptions {
    status?: number;      // default: 500
    message?: string;     // default: "Internal server error"
    messageError?: any;
    [key: string]: any;   // for any additional properties
}


export default class ResponseUtil {


    static success = <T>(
        res: Response,
        { status = 200, message = "", response = {} as T, ...extra }: SuccessOptions<T>
    ) => {
        return res.status(status).json({
            error: false,
            message,
            response,
            ...extra
        });
    }

    static error = (res: Response, { status = 500, message = "Internal server error", messageError, ...extra }: ErrorOptions) => {
        return res.status(status).json({
            error: true,
            message,
            response: {},
            ...(process.env.NODE_ENV === "development" && messageError
                ? { messageError }
                : {}),
            ...extra,
        });
    }
}
