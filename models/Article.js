const db = require('../database/db');

class Article {
    static async create(articleData) {
        try {
            const { title, content, excerpt, image_url, author_id } = articleData;
            
            const result = await db.run(
                `INSERT INTO articles (title, content, excerpt, image_url, author_id, created_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
                [title, content, excerpt, image_url, author_id]
            );
            
            return { id: result.id, ...articleData };
        } catch (error) {
            console.error('Error creating article:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            const article = await db.get(
                `SELECT a.*, u.username as author_name 
                 FROM articles a 
                 LEFT JOIN users u ON a.author_id = u.id 
                 WHERE a.id = ? AND a.deleted = 0`,
                [id]
            );
            return article;
        } catch (error) {
            console.error('Error finding article by ID:', error);
            throw error;
        }
    }

    static async getAll(limit = null) {
        try {
            let query = `SELECT a.*, u.username as author_name 
                        FROM articles a 
                        LEFT JOIN users u ON a.author_id = u.id 
                        WHERE a.deleted = 0 
                        ORDER BY a.created_at DESC`;
            
            if (limit) {
                query += ` LIMIT ${limit}`;
            }
            
            const articles = await db.all(query);
            return articles;
        } catch (error) {
            console.error('Error getting all articles:', error);
            throw error;
        }
    }

    static async update(id, articleData) {
        try {
            const { title, content, excerpt, image_url } = articleData;
            
            const result = await db.run(
                `UPDATE articles 
                 SET title = ?, content = ?, excerpt = ?, image_url = ?, updated_at = datetime('now')
                 WHERE id = ? AND deleted = 0`,
                [title, content, excerpt, image_url, id]
            );
            
            return result.changes > 0;
        } catch (error) {
            console.error('Error updating article:', error);
            throw error;
        }
    }

    static async softDelete(id) {
        try {
            const result = await db.run(
                `UPDATE articles SET deleted = 1, updated_at = datetime('now') WHERE id = ?`,
                [id]
            );
            
            return result.changes > 0;
        } catch (error) {
            console.error('Error soft deleting article:', error);
            throw error;
        }
    }

    static async getPublished(limit = null) {
        try {
            let query = `SELECT a.*, u.username as author_name 
                        FROM articles a 
                        LEFT JOIN users u ON a.author_id = u.id 
                        WHERE a.deleted = 0 AND a.published = 1 
                        ORDER BY a.created_at DESC`;
            
            if (limit) {
                query += ` LIMIT ${limit}`;
            }
            
            const articles = await db.all(query);
            return articles;
        } catch (error) {
            console.error('Error getting published articles:', error);
            throw error;
        }
    }

    static async publish(id) {
        try {
            const result = await db.run(
                `UPDATE articles 
                 SET published = 1, updated_at = datetime('now')
                 WHERE id = ? AND deleted = 0`,
                [id]
            );
            
            return result.changes > 0;
        } catch (error) {
            console.error('Error publishing article:', error);
            throw error;
        }
    }

    static async unpublish(id) {
        try {
            const result = await db.run(
                `UPDATE articles 
                 SET published = 0, updated_at = datetime('now')
                 WHERE id = ? AND deleted = 0`,
                [id]
            );
            
            return result.changes > 0;
        } catch (error) {
            console.error('Error unpublishing article:', error);
            throw error;
        }
    }
}

module.exports = Article;
