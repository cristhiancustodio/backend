import { prisma } from "../lib/prisma";

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

            return res.status(200).json({ message: 'List of posts', data: newList });
        } catch (error) {
            return res.status(500).json({ error: 'Internal server error', details: error.message });
        }
    }

    static async getPostById(req, res) {
        try {

            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return res.status(400).json({ error: 'Post ID is required' });
            }

            const listaPost = await prisma.publications.findFirst({
                where: { active: true, idPublication: idPost }
            });
            if (!listaPost) {
                return res.status(404).json({ error: 'Post not found' });
            }

            const listFormat = {
                ...listaPost,
                comments: await prisma.comments.findMany({
                    where: {
                        active: true,
                        idPublication: idPost
                    },
                })
            }


            return res.status(200).json({ message: 'List of posts', data: listFormat });
        } catch (error) {
            return res.status(500).json({ error: 'Internal server error', details: error.message });
        }
    }

    static async createPost(req, res) {
        try {
            const { title, content } = req.body;

            if (!title || !content) {
                return res.status(400).json({ error: 'Title and content are required' });
            }

            const newPost = await prisma.publications.create({
                data: {
                    title,
                    content,
                    idUser: 1,
                }
            });

            return res.status(201).json({ message: 'Post created successfully', data: newPost });

        } catch (error) {
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    static async updatePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return res.status(400).json({ error: 'Post ID is required' });
            }

            const { title, content } = req.body;

            if (!title || !content) {
                return res.status(400).json({ error: 'Title and content are required' });
            }

            const updatedPost = await prisma.publications.update({
                where: { idPublication: idPost },
                data: {
                    title,
                    content
                }
            });

            return res.status(200).json({ message: 'Post updated successfully', data: updatedPost });

        } catch (error) {
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    static async deletePost(req, res) {
        try {
            const idPost = +(req.params.id || 0);
            if (idPost === 0) {
                return res.status(400).json({ error: 'Post ID is required' });
            }

            await prisma.publications.delete({
                where: { idPublication: idPost }
            });

            return res.status(200).json({ message: 'Post deleted successfully' });
        } catch (error) {
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
}