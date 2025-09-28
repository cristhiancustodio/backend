
import { Router } from "express";
import { PostController } from "../controllers/PostController";
import { CommentController } from "../controllers/CommentController";
import { body } from "express-validator";
import { handleInputErrors } from "../middleware/validation";

const postRoutes = Router();

postRoutes.get("/", PostController.getAllPosts);

postRoutes.post("/", PostController.createPost);

postRoutes.get("/:id", PostController.getPostById);

postRoutes.put("/:id", (req, res) => {

});

postRoutes.delete("/:id", (req, res) => {

});


postRoutes.post("/:id/comments",
    body('content').notEmpty().withMessage('Content is required'),
    handleInputErrors,
    CommentController.createComment);

postRoutes.put("/:id/comments/:commentId",
    CommentController.updateLikesComment);

postRoutes.delete("/:id/comments/:commentId",
    CommentController.deleteComment);




export default postRoutes;
