import { prisma } from "../lib/prisma";
import ResponseUtil from "../utils/Response";


export class CommentController {

    static async createComment(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return ResponseUtil.error(res, { status: 404, message: 'Post ID is required' });
            }
            const { content } = req.body;
            const response = await prisma.comments.create({
                data: {
                    content,
                    idPublication: idPost,
                    idUser: 1,
                }
            });

            return ResponseUtil.success(res, { message: 'Comment created successfully', response });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
    static async deleteComment(req, res) {
        try {
            const idComment = +(req.params.commentId || 0);
            if (idComment === 0) {
                return ResponseUtil.error(res, { status: 404, message: 'Comment ID is required' });
            }
            const find = await prisma.comments.findUnique({ where: { idComment: idComment } });

            if (!find) {
                return ResponseUtil.error(res, { status: 404, message: 'Comment not found' });
            }
            await prisma.comments.delete({ where: { idComment: idComment } });
            return ResponseUtil.success(res, { message: 'Comment deleted successfully', response: {} });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
    static async updateLikesComment(req, res) {
        try {
            const idComment = +(req.params.commentId || 0);
            if (idComment === 0) {
                return ResponseUtil.error(res, { status: 404, message: 'Comment ID is required' });
            }
            const content = req.body;

            const find = await prisma.comments.findUnique({ where: { idComment: idComment } });

            if (!find) {
                return ResponseUtil.error(res, { status: 404, message: 'Comment not found' });
            }
            let likes = content.likes === true ? find.likes + 1 : find.likes - 1;

            const response = await prisma.comments.update({
                where: { idComment: idComment },
                data: { likes: likes }
            });
            return ResponseUtil.success(res, { message: 'Likes updated successfully', response });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
    static async getCommentById(req, res) {
        try {

            return ResponseUtil.success(res, { message: 'Comment retrieved successfully', response: {} });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

}