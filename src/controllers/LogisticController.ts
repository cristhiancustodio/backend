import { prisma } from "../lib/prisma";
import ResponseUtil from "../utils/response";
export class LogisticController {

    static async getCountrysAndProvinces(req, res) {
        try {
            const countrys = await prisma.pais.findMany();
            const provinces = await prisma.provincia.findMany();
            return ResponseUtil.success(res, {
                status: 200,
                message: "Countrys and Provinces retrieved successfully",
                response: {
                    countrys,
                    provinces
                }
            });
        } catch (error) {

        }
    }
}