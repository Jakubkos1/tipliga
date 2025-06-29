const db = require('../database/db');

class User {
    static async findByDiscordId(discordId) {
        try {
            // Check if using Supabase API or SQLite
            if (db.findUserByDiscordId) {
                return await db.findUserByDiscordId(discordId);
            } else {
                const user = await db.get(
                    'SELECT * FROM users WHERE discord_id = ?',
                    [discordId]
                );
                return user;
            }
        } catch (error) {
            console.error('Error finding user by Discord ID:', error);
            throw error;
        }
    }

    static async create(userData) {
        try {
            const { discordId, username, avatarUrl } = userData;

            // Check if using Supabase API or SQLite
            if (db.createUser) {
                // Using Supabase API
                console.log('👤 Creating user with Supabase API:', { discordId, username, avatarUrl });
                const newUser = await db.createUser({
                    discord_id: discordId,
                    username: username,
                    avatar_url: avatarUrl
                });
                console.log('✅ Created user:', newUser);
                return newUser;
            } else {
                // Using SQLite
                const isPostgres = !!(process.env.DATABASE_URL || process.env.POSTGRES_URL);

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
            }
        } catch (error) {
            console.error('Error creating user:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            // Check if using Supabase API or SQLite
            if (db.get && typeof db.get === 'function' && !db.apiQuery) {
                // Using SQLite
                const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
                return user;
            } else {
                // Using Supabase API
                const users = await db.apiQuery('users', {
                    filter: `id=eq.${id}`,
                    select: '*'
                });
                return users[0] || null;
            }
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
                if (db.updateUser) {
                    // Using Supabase API
                    await db.updateUser(existingUser.id, {
                        username: username,
                        avatar_url: discordProfile.avatar,
                        updated_at: new Date().toISOString()
                    });
                } else {
                    // Using SQLite
                    await db.run(
                        'UPDATE users SET username = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?',
                        [username, discordProfile.avatar, discordProfile.id]
                    );
                }
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
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API - calculate leaderboard in JavaScript
                const users = await db.apiQuery('users', { select: '*' });
                const predictions = await db.apiQuery('predictions', { select: '*' });
                const matches = await db.apiQuery('matches', { select: '*' });

                // Filter out predictions for deleted matches
                const validPredictions = predictions.filter(prediction => {
                    const match = matches.find(m => m.id === prediction.match_id);
                    return match && !match.deleted;
                });

                // Calculate stats for each user
                const leaderboard = users.map(user => {
                    const userPredictions = validPredictions.filter(p => p.user_id === user.id);
                    const total_predictions = userPredictions.length;
                    const total_points = userPredictions.reduce((sum, p) => sum + (p.points_earned || 0), 0);
                    const correct_predictions = userPredictions.filter(p => p.points_earned > 0).length;

                    return {
                        username: user.username,
                        avatar_url: user.avatar_url,
                        total_predictions,
                        total_points,
                        correct_predictions
                    };
                })
                .filter(user => user.total_predictions > 0) // Only users with predictions
                .sort((a, b) => {
                    // Sort by total_points DESC, then correct_predictions DESC
                    if (b.total_points !== a.total_points) {
                        return b.total_points - a.total_points;
                    }
                    return b.correct_predictions - a.correct_predictions;
                });

                return leaderboard;
            } else {
                // Using SQLite
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
            }
        } catch (error) {
            console.error('Error getting leaderboard:', error);
            throw error;
        }
    }

    // User management methods
    static async getAllUsers() {
        try {
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API - calculate stats in JavaScript
                const users = await db.apiQuery('users', {
                    select: '*',
                    order: 'created_at.desc'
                });
                const predictions = await db.apiQuery('predictions', { select: '*' });
                const matches = await db.apiQuery('matches', { select: '*' });

                // Filter out predictions for deleted matches
                const validPredictions = predictions.filter(prediction => {
                    const match = matches.find(m => m.id === prediction.match_id);
                    return match && !match.deleted;
                });

                // Calculate stats for each user
                const usersWithStats = users.map(user => {
                    const userPredictions = validPredictions.filter(p => p.user_id === user.id);
                    const total_predictions = userPredictions.length;
                    const correct_predictions = userPredictions.filter(p => p.points_earned > 0).length;
                    const total_points = userPredictions.reduce((sum, p) => sum + (p.points_earned || 0), 0);

                    return {
                        ...user,
                        total_predictions,
                        correct_predictions,
                        total_points
                    };
                });

                return usersWithStats;
            } else {
                // Using SQLite
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
            }
        } catch (error) {
            console.error('Error getting all users:', error);
            throw error;
        }
    }

    static async updateUserRole(userId, role) {
        try {
            // Validate role
            const validRoles = ['user', 'moderator', 'admin'];
            if (!validRoles.includes(role)) {
                throw new Error('Invalid role');
            }

            console.log(`🔄 Updating user ${userId} role to ${role}...`);

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                const result = await db.apiQuery('users', {
                    method: 'PATCH',
                    filter: `id=eq.${userId}`,
                    body: {
                        role: role,
                        updated_at: new Date().toISOString()
                    }
                });
                console.log(`✅ Supabase role update result:`, result);
            } else {
                // Using SQLite
                await db.run(
                    'UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [role, userId]
                );
            }

            console.log(`✅ User ${userId} role updated to ${role}`);
            return await this.findById(userId);
        } catch (error) {
            console.error('❌ Error updating user role:', error);
            throw error;
        }
    }

    static async resetUserStats(userId) {
        try {
            console.log(`🔄 Resetting statistics for user ${userId}...`);

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                const result = await db.apiQuery('predictions', {
                    method: 'DELETE',
                    filter: `user_id=eq.${userId}`
                });
                console.log(`✅ Supabase delete predictions result:`, result);
            } else {
                // Using SQLite
                await db.run('DELETE FROM predictions WHERE user_id = ?', [userId]);
            }

            console.log(`✅ Reset statistics for user ID: ${userId}`);
            return true;
        } catch (error) {
            console.error('❌ Error resetting user stats:', error);
            throw error;
        }
    }

    static async deleteUser(userId) {
        try {
            console.log(`🔄 Deleting user ${userId}...`);

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                // First delete all predictions
                await db.apiQuery('predictions', {
                    method: 'DELETE',
                    filter: `user_id=eq.${userId}`
                });

                // Then delete the user
                const result = await db.apiQuery('users', {
                    method: 'DELETE',
                    filter: `id=eq.${userId}`
                });
                console.log(`✅ Supabase delete user result:`, result);
            } else {
                // Using SQLite
                // First delete all predictions (cascade should handle this, but being explicit)
                await db.run('DELETE FROM predictions WHERE user_id = ?', [userId]);

                // Then delete the user
                await db.run('DELETE FROM users WHERE id = ?', [userId]);
            }

            console.log(`✅ Deleted user ID: ${userId}`);
            return true;
        } catch (error) {
            console.error('❌ Error deleting user:', error);
            throw error;
        }
    }
}

module.exports = User;
