
import { Router } from "express";
import { PostController } from "../controllers/PostController";

const postRoutes = Router();

postRoutes.get("/", PostController.getAllPosts);

postRoutes.post("/", PostController.createPost);

postRoutes.get("/:id", PostController.getPostById);

postRoutes.put("/:id", (req, res) => {

});

postRoutes.delete("/:id", (req, res) => {

});



export default postRoutes;
