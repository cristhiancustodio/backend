import { Router } from "express";
import { body } from "express-validator";
import { handleInputErrors } from "../middleware/validation";
import { authenticate } from "../middleware/authV2";
import { LogisticController } from "../controllers/LogisticController";


const logisticRoutes = Router();

logisticRoutes.use(authenticate);

logisticRoutes.get("/cities", LogisticController.getCountrysAndProvinces);

export default logisticRoutes;






