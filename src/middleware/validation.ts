import type { Request, Response, NextFunction } from 'express'
import { validationResult } from 'express-validator'
import ResponseUtil from '../utils/response'


export const handleInputErrors = (req: Request, res: Response, next: NextFunction) => {
    let errors = validationResult(req)
    if (!errors.isEmpty()) {
        return ResponseUtil.error(res, { status: 400, message: 'Invalid input', messageError: errors.array()})
    }
    return next();
}