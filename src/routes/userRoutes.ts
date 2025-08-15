import { Router } from "express";
import { authenticate } from "../middleware/auth";


const userRoutes = Router();

userRoutes.use(authenticate);


userRoutes.get('/', (req, res) => {
    try {
        
        
        return res.status(200).json({
            code: 200,
            error: false,
            message: 'User route'
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: 'Internal server error'
        });
    }
});

export default userRoutes;
