import { prisma } from "../lib/prisma";
import ResponseUtil from "../utils/Response";

export class PostController {
    static async getAllPosts(req, res) {
        try {
            const listaPost = await prisma.publications.findMany({
                where: { active: true, idUser: req?.id || 1 }
            });
            const comments = await prisma.comments.findMany({
                where: {
                    active: true,
                    idPublication: { in: listaPost.map(post => post.idPublication) }
                },
            });
            const newList = listaPost.map((post) => {

                let comm = comments.filter(comment => comment.idPublication === post.idPublication);
                return { ...post, comments: comm };
            });

            return ResponseUtil.success(res, { message: 'List of posts', response: newList });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

    static async getPostById(req, res) {
        try {

            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return ResponseUtil.error(res, {
                    status: 400,
                    message: 'Post ID is required',
                });
            }
            const listaPost = await prisma.publications.findFirst({
                where: { active: true, idPublication: idPost }
            });
            if (!listaPost) {
                return ResponseUtil.error(res, { status: 404, message: 'Post not found' });
            }

            const listFormat = {
                ...listaPost,
                comments: await prisma.comments.findMany({
                    where: {
                        active: true,
                        idPublication: idPost
                    },
                    orderBy: { createdAt: 'desc' }
                })
            }

            return ResponseUtil.success(res, {
                message: 'Post retrieved successfully', response: listFormat
            });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

    static async createPost(req, res) {
        try {
            const { title, content } = req.body;
            if (!title || !content) {
                return ResponseUtil.error(res, { status: 400, message: 'Title and content are required' });
            }
            const newPost = await prisma.publications.create({
                data: {
                    title,
                    content,
                    idUser: 1,
                }
            });
            return ResponseUtil.success(res, { message: 'Post created successfully', response: newPost });

        } catch (error) {
            return error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

    static async updatePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return ResponseUtil.error(res, { status: 400, message: 'Post ID is required' });
            }

            const { title, content } = req.body;

            if (!title || !content) {
                return ResponseUtil.error(res, { status: 400, message: 'Title and content are required' });
            }

            const updatedPost = await prisma.publications.update({
                where: { idPublication: idPost },
                data: {
                    title,
                    content
                }
            });

            return ResponseUtil.success(res, { message: 'Post updated successfully', response: updatedPost });

        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

    static async deletePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return ResponseUtil.error(res, { status: 400, message: 'Post ID is required' });
            }

            await prisma.publications.delete({
                where: { idPublication: idPost }
            });

            return ResponseUtil.success(res, { message: 'Post deleted successfully' });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
}