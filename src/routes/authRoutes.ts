import { Router } from 'express'
import { body, param } from 'express-validator'
import { PrismaClient } from '@prisma/client'
import { authenticate } from '../middleware/auth'
import { handleInputErrors } from '../middleware/validation'
import { AuthController } from '../controllers/authController'


const authRoutes = Router()


/**
 * Endpoint to request a new email confirmation code
 */
authRoutes.post("/newCode", AuthController.newCode);

authRoutes.post('/login',
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
    handleInputErrors,
    AuthController.login
);

authRoutes.post("/register", AuthController.register);

/** Endpoint to change password when user is authenticated */
authRoutes.put('/changePassword',
    authenticate,
    body('oldPassword').notEmpty().isString().withMessage('Old password is required'),
    body('newPassword').notEmpty().isString().withMessage('New password is required'),
    handleInputErrors,
    AuthController.changePassword
);

/**Endpoint for password reset without authentication*/
authRoutes.post("/reset-password",
    body("newPassword").isString().notEmpty().withMessage("New password is required"),
    body("token").isString().notEmpty().withMessage("Token is required"),

    handleInputErrors,
    AuthController.resetPassword
);

authRoutes.post("/forgot-password",
    body("email").isEmail(),
    handleInputErrors,
    AuthController.forgotPassword
);


/* Endpoint to confirm email with a code */
authRoutes.post('/confirmed', AuthController.confirmedAccount);
/** Endpoint to refresh access token */
authRoutes.post("/refresh", AuthController.refreshToken);

authRoutes.post('/logout', AuthController.logOut);

authRoutes.get('/me', authenticate, AuthController.getMe);

export default authRoutes