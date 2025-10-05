
import { Router } from "express";
import { PostController } from "../controllers/PostController";
import { CommentController } from "../controllers/CommentController";
import { body } from "express-validator";
import { handleInputErrors } from "../middleware/validation";
import { authenticate } from "../middleware/auth";

const postRoutes = Router();

//postRoutes.use(authenticate);

postRoutes.get("/", PostController.getAllPosts);

postRoutes.post("/", PostController.createPost);

postRoutes.get("/:id", PostController.getPostById);

postRoutes.put("/:id", (req, res) => { });

postRoutes.delete("/:id", (req, res) => { });

postRoutes.put("/:id/like", PostController.likePost);




//Crear nuevo comentario
postRoutes.post("/:id/comments",
    body('content').notEmpty().withMessage('Content is required'),
    handleInputErrors, CommentController.createComment);

//Eliminar comentario
postRoutes.delete("/:id/comments/:commentId", CommentController.deleteComment);

postRoutes.put("/:id/comments/:commentId", CommentController.updateComment);


//Actualizar likes comentario
postRoutes.post("/:id/comments/:commentId/like", CommentController.updateLikesComment);




export default postRoutes;
