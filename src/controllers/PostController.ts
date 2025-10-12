import { Comments } from "@prisma/client";
import { prisma } from "../lib/prisma";
import ResponseUtil from "../utils/response";

export class PostController {
    static async getAllPosts(req, res) {
        try {
            const listaPost = await prisma.publications.findMany({
                where: { active: true, idUser: req?.id || 1 },
                orderBy: { createdAt: 'desc' },
            });
            const comments = await prisma.comments.findMany({
                where: {
                    active: true,
                    idPublication: { in: listaPost.map(post => post.idPublication) }
                },
            });

            const likes = await prisma.like.findMany({
                where: {
                    idPublication: { in: listaPost.map(post => post.idPublication) },
                    idComment: null
                },
                select: { idLike: true, idPublication: true, idComment: true, userId: true }
            });

            let countlikes = {};
            likes.forEach(element => {
                if (countlikes[element.idPublication]) {
                    countlikes[element.idPublication].count += 1;
                } else {
                    countlikes[element.idPublication] = { count: 1 };
                }

                if (element.userId === 1) {
                    countlikes[element.idPublication].meLikes = true;
                }
            });

            const newList = listaPost.map((post) => {
                let comm = comments.filter(comment => comment.idPublication === post.idPublication);
                return { ...post, comments: comm, likes: countlikes[post.idPublication]?.count || 0, meLikes: countlikes[post.idPublication]?.meLikes || false };
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

            const likes = await prisma.like.findMany({ where: { idPublication: idPost } });
            const formatLikesPost = {};
            const formatLikesComments = {};
            const formatMeLikesComments = {};

            let meLikes = likes.some(like => !like.idComment && like.userId === 1);
            likes.forEach(like => {

                if (like.idComment) {

                    if (formatLikesComments[like.idComment]) {
                        formatLikesComments[like.idComment] += 1;
                    } else {
                        formatLikesComments[like.idComment] = 1;
                    }
                } else {
                    listaPost.likes += 1;

                }
                if (like.userId === 1) {
                    formatMeLikesComments[like.idComment] = true;
                }
            });
            const comments = await prisma.comments.findMany({
                where: {
                    active: true,
                    idPublication: idPost
                },
                orderBy: { createdAt: 'desc' },
            })

            const listFormat = {
                ...listaPost,
                meLikes,
                comments: comments.filter(comment => !comment.idReply)
            }
            listFormat.comments = listFormat.comments.map(comment => ({
                ...comment,
                likes: formatLikesComments[comment.idComment] || 0,
                meLikes: formatMeLikesComments[comment.idComment] || false,
                replys: PostController.formatCommentsReplys(comments, comment.idComment, formatMeLikesComments, formatLikesComments)
            }));

            return ResponseUtil.success(res, {
                message: 'Post retrieved successfully', response: listFormat
            });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }

    //Metodo para formatear los comentarios y sus respectivas respuestas
    static formatCommentsReplys(comments: Comments[], idComment: Comments['idComment'], formatMeLikesComments: any, formatLikesComments: any) {
        const replys = comments.filter(c => c.idReply === idComment);
        return replys.map(reply => ({
            ...reply,
            meLikes: formatMeLikesComments[reply.idComment] || false,
            likes: formatLikesComments[reply.idComment] || 0,
            replys: PostController.formatCommentsReplys(comments, reply.idComment, formatMeLikesComments, formatLikesComments)
        }));
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
    static async likePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return ResponseUtil.error(res, { status: 404, message: 'Post ID is required' });
            }

            const find = await prisma.like.findFirst({
                where: { idPublication: idPost, userId: 1, OR: [{ idComment: null }, { idComment: 0 }] }
            });
            if (find) {
                await prisma.like.delete({ where: { idLike: find.idLike } });
            } else {
                await prisma.like.create({ data: { idPublication: idPost, userId: 1 } });
            }
            return ResponseUtil.success(res, { message: 'Likes updated successfully' });
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

    static async savePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);

            const found = await prisma.savedPost.findFirst({ where: { idPublication: idPost, idUser: 1 } });
            if (!found) {
                await prisma.savedPost.create({ data: { idPublication: idPost, idUser: 1 } });
            } else {
                await prisma.savedPost.delete({ where: { id: found.id } });
            }
            return ResponseUtil.success(res, { message: 'Post saved' });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
    static async reportPost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            const found = await prisma.savedPost.findFirst({ where: { idPublication: idPost } });
            if (!found) {
                return ResponseUtil.error(res, { status: 422, message: 'Post not found' });
            }
            await prisma.report.create({ data: { reason: req.body.reason, idPublication: idPost, userId: 1 } });
            return ResponseUtil.success(res, { message: 'Reported publication' });
        } catch (error) {
            return ResponseUtil.error(res, { status: 500, message: 'Internal server error', messageError: error.message });
        }
    }
}