const db = require('../database/db');

class Article {
    static async create(articleData) {
        try {
            const { title, content, excerpt, image_url, author_id } = articleData;

            // For Supabase API, we need to use simple table operations
            const articleToCreate = {
                title,
                content,
                excerpt,
                image_url,
                author_id,
                published: 1,
                deleted: 0,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            const result = await db.apiQuery('articles', {
                method: 'POST',
                body: articleToCreate
            });

            return result[0];
        } catch (error) {
            console.error('Error creating article:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            // Get article first
            const article = await db.get('articles', `id=eq.${id}&deleted=eq.0`);

            if (article && article.author_id) {
                // Get author info separately
                const author = await db.get('users', `id=eq.${article.author_id}`);
                if (author) {
                    article.author_name = author.username;
                }
            }

            return article;
        } catch (error) {
            console.error('Error finding article by ID:', error);
            throw error;
        }
    }

    static async getAll(limit = null) {
        try {
            // Get articles ordered by creation date
            let filter = 'deleted=eq.0&order=created_at.desc';
            if (limit) {
                filter += `&limit=${limit}`;
            }

            const articles = await db.all('articles', filter);

            // Get author names for each article
            for (const article of articles) {
                if (article.author_id) {
                    const author = await db.get('users', `id=eq.${article.author_id}`);
                    if (author) {
                        article.author_name = author.username;
                    }
                }
            }

            return articles;
        } catch (error) {
            console.error('Error getting all articles:', error);
            throw error;
        }
    }

    static async getWithPagination(limit = 10, offset = 0, search = '') {
        try {
            let filter = 'deleted=eq.0&published=eq.1&order=created_at.desc';
            let countFilter = 'deleted=eq.0&published=eq.1';

            // Add search functionality
            if (search && search.trim()) {
                const searchTerm = search.trim();
                // Search in title, content, and excerpt
                const searchCondition = `and=(or(title.ilike.*${searchTerm}*,content.ilike.*${searchTerm}*,excerpt.ilike.*${searchTerm}*))`;
                filter += `&${searchCondition}`;
                countFilter += `&${searchCondition}`;
            }

            // Add pagination
            filter += `&limit=${limit}&offset=${offset}`;

            // Get articles with pagination
            const articles = await db.all('articles', filter);

            // Get total count for pagination (without limit/offset)
            const allMatchingArticles = await db.all('articles', countFilter);
            const totalCount = allMatchingArticles.length;

            // Get author names for each article
            for (const article of articles) {
                if (article.author_id) {
                    const author = await db.get('users', `id=eq.${article.author_id}`);
                    if (author) {
                        article.author_name = author.username;
                    }
                }
            }

            return {
                articles: articles,
                total: totalCount
            };
        } catch (error) {
            console.error('Error getting articles with pagination:', error);
            throw error;
        }
    }

    static async update(id, articleData) {
        try {
            const { title, content, excerpt, image_url } = articleData;

            const updateData = {
                title,
                content,
                excerpt,
                image_url,
                updated_at: new Date().toISOString()
            };

            const result = await db.apiQuery('articles', {
                method: 'PATCH',
                filter: `id=eq.${id}&deleted=eq.0`,
                body: updateData
            });

            return result && result.length > 0;
        } catch (error) {
            console.error('Error updating article:', error);
            throw error;
        }
    }

    static async softDelete(id) {
        try {
            const updateData = {
                deleted: 1,
                updated_at: new Date().toISOString()
            };

            const result = await db.apiQuery('articles', {
                method: 'PATCH',
                filter: `id=eq.${id}`,
                body: updateData
            });

            return result && result.length > 0;
        } catch (error) {
            console.error('Error soft deleting article:', error);
            throw error;
        }
    }

    static async getPublished(limit = null) {
        try {
            // Get published articles ordered by creation date
            let filter = 'deleted=eq.0&published=eq.1&order=created_at.desc';
            if (limit) {
                filter += `&limit=${limit}`;
            }

            const articles = await db.all('articles', filter);

            // Get author names for each article
            for (const article of articles) {
                if (article.author_id) {
                    const author = await db.get('users', `id=eq.${article.author_id}`);
                    if (author) {
                        article.author_name = author.username;
                    }
                }
            }

            return articles;
        } catch (error) {
            console.error('Error getting published articles:', error);
            throw error;
        }
    }

    static async publish(id) {
        try {
            const updateData = {
                published: 1,
                updated_at: new Date().toISOString()
            };

            const result = await db.apiQuery('articles', {
                method: 'PATCH',
                filter: `id=eq.${id}&deleted=eq.0`,
                body: updateData
            });

            return result && result.length > 0;
        } catch (error) {
            console.error('Error publishing article:', error);
            throw error;
        }
    }

    static async unpublish(id) {
        try {
            const updateData = {
                published: 0,
                updated_at: new Date().toISOString()
            };

            const result = await db.apiQuery('articles', {
                method: 'PATCH',
                filter: `id=eq.${id}&deleted=eq.0`,
                body: updateData
            });

            return result && result.length > 0;
        } catch (error) {
            console.error('Error unpublishing article:', error);
            throw error;
        }
    }
}

module.exports = Article;
