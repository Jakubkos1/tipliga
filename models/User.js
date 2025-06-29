const db = require('../database/db');

class User {
    static async findByDiscordId(discordId) {
        try {
            const user = await db.get(
                'SELECT * FROM users WHERE discord_id = ?',
                [discordId]
            );
            return user;
        } catch (error) {
            console.error('Error finding user by Discord ID:', error);
            throw error;
        }
    }

    static async create(userData) {
        try {
            const { discordId, username, avatarUrl } = userData;

            // Use PostgreSQL RETURNING clause or SQLite lastID
            const isPostgres = !!process.env.DATABASE_URL;

            if (isPostgres) {
                const result = await db.query(
                    'INSERT INTO users (discord_id, username, avatar_url) VALUES ($1, $2, $3) RETURNING id',
                    [discordId, username, avatarUrl]
                );
                const userId = result.rows[0].id;
                return await this.findById(userId);
            } else {
                const result = await db.run(
                    'INSERT INTO users (discord_id, username, avatar_url) VALUES (?, ?, ?)',
                    [discordId, username, avatarUrl]
                );
                return await this.findById(result.id);
            }
        } catch (error) {
            console.error('Error creating user:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
            return user;
        } catch (error) {
            console.error('Error finding user by ID:', error);
            throw error;
        }
    }

    static async updateOrCreate(discordProfile) {
        try {
            console.log('👤 Processing Discord profile in User model:', discordProfile);

            const existingUser = await this.findByDiscordId(discordProfile.id);

            // Create proper username with discriminator if it exists
            const username = discordProfile.discriminator
                ? `${discordProfile.username}#${discordProfile.discriminator}`
                : discordProfile.username;

            if (existingUser) {
                console.log('👤 Updating existing user:', existingUser.id);
                // Update existing user
                await db.run(
                    'UPDATE users SET username = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?',
                    [username, discordProfile.avatar, discordProfile.id]
                );
                return await this.findByDiscordId(discordProfile.id);
            } else {
                console.log('👤 Creating new user');
                // Create new user
                return await this.create({
                    discordId: discordProfile.id,
                    username: username,
                    avatarUrl: discordProfile.avatar
                });
            }
        } catch (error) {
            console.error('Error updating or creating user:', error);
            throw error;
        }
    }

    static async getLeaderboard() {
        try {
            const leaderboard = await db.all(`
                SELECT 
                    u.username,
                    u.avatar_url,
                    COUNT(p.id) as total_predictions,
                    SUM(p.points_earned) as total_points,
                    COUNT(CASE WHEN p.points_earned > 0 THEN 1 END) as correct_predictions
                FROM users u
                LEFT JOIN predictions p ON u.id = p.user_id
                GROUP BY u.id, u.username, u.avatar_url
                HAVING total_predictions > 0
                ORDER BY total_points DESC, correct_predictions DESC
            `);
            return leaderboard;
        } catch (error) {
            console.error('Error getting leaderboard:', error);
            throw error;
        }
    }

    // User management methods
    static async getAllUsers() {
        try {
            const users = await db.all(`
                SELECT
                    u.*,
                    COUNT(p.id) as total_predictions,
                    SUM(CASE WHEN p.points_earned > 0 THEN 1 ELSE 0 END) as correct_predictions,
                    SUM(p.points_earned) as total_points
                FROM users u
                LEFT JOIN predictions p ON u.id = p.user_id
                GROUP BY u.id
                ORDER BY u.created_at DESC
            `);
            return users;
        } catch (error) {
            console.error('Error getting all users:', error);
            throw error;
        }
    }

    static async updateUserRole(userId, role) {
        try {
            // Validate role
            const validRoles = ['user', 'moderator'];
            if (!validRoles.includes(role)) {
                throw new Error('Invalid role');
            }

            await db.run(
                'UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [role, userId]
            );

            return await this.findById(userId);
        } catch (error) {
            console.error('Error updating user role:', error);
            throw error;
        }
    }

    static async resetUserStats(userId) {
        try {
            // Delete all predictions for the user
            await db.run('DELETE FROM predictions WHERE user_id = ?', [userId]);
            console.log(`✅ Reset statistics for user ID: ${userId}`);
            return true;
        } catch (error) {
            console.error('Error resetting user stats:', error);
            throw error;
        }
    }

    static async deleteUser(userId) {
        try {
            // First delete all predictions (cascade should handle this, but being explicit)
            await db.run('DELETE FROM predictions WHERE user_id = ?', [userId]);

            // Then delete the user
            await db.run('DELETE FROM users WHERE id = ?', [userId]);

            console.log(`✅ Deleted user ID: ${userId}`);
            return true;
        } catch (error) {
            console.error('Error deleting user:', error);
            throw error;
        }
    }
}

module.exports = User;
