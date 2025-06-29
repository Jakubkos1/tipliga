const db = require('../database/db');

class Prediction {
    static async create(predictionData) {
        try {
            const { userId, matchId, predictedWinner } = predictionData;
            
            // Use INSERT OR REPLACE to handle updates
            const result = await db.run(`
                INSERT OR REPLACE INTO predictions (user_id, match_id, predicted_winner, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            `, [userId, matchId, predictedWinner]);
            
            return await this.findById(result.id);
        } catch (error) {
            console.error('Error creating/updating prediction:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            const prediction = await db.get('SELECT * FROM predictions WHERE id = ?', [id]);
            return prediction;
        } catch (error) {
            console.error('Error finding prediction by ID:', error);
            throw error;
        }
    }

    static async findByUserAndMatch(userId, matchId) {
        try {
            const prediction = await db.get(
                'SELECT * FROM predictions WHERE user_id = ? AND match_id = ?',
                [userId, matchId]
            );
            return prediction;
        } catch (error) {
            console.error('Error finding prediction by user and match:', error);
            throw error;
        }
    }

    static async getUserPredictions(userId) {
        try {
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API - need to do separate queries and join in JavaScript
                const predictions = await db.apiQuery('predictions', {
                    filter: `user_id=eq.${userId}`,
                    select: '*'
                });

                // Get match details for each prediction
                const predictionsWithMatches = await Promise.all(predictions.map(async (prediction) => {
                    const matches = await db.apiQuery('matches', {
                        filter: `id=eq.${prediction.match_id}`,
                        select: '*'
                    });
                    const match = matches[0];

                    return {
                        ...prediction,
                        team_a: match?.team_a,
                        team_b: match?.team_b,
                        match_time: match?.match_time,
                        winner: match?.winner,
                        status: match?.status
                    };
                }));

                // Sort by match_time DESC
                return predictionsWithMatches.sort((a, b) =>
                    new Date(b.match_time) - new Date(a.match_time)
                );
            } else {
                // Using SQLite
                const predictions = await db.all(`
                    SELECT
                        p.*,
                        m.team_a,
                        m.team_b,
                        m.match_time,
                        m.winner,
                        m.status
                    FROM predictions p
                    JOIN matches m ON p.match_id = m.id
                    WHERE p.user_id = ?
                    ORDER BY m.match_time DESC
                `, [userId]);

                return predictions;
            }
        } catch (error) {
            console.error('Error getting user predictions:', error);
            throw error;
        }
    }

    static async getMatchPredictions(matchId) {
        try {
            const predictions = await db.all(`
                SELECT 
                    p.*,
                    u.username,
                    u.avatar_url
                FROM predictions p
                JOIN users u ON p.user_id = u.id
                WHERE p.match_id = ?
                ORDER BY p.created_at ASC
            `, [matchId]);
            
            return predictions;
        } catch (error) {
            console.error('Error getting match predictions:', error);
            throw error;
        }
    }

    static async getStats() {
        try {
            const stats = await db.get(`
                SELECT 
                    COUNT(*) as total_predictions,
                    COUNT(DISTINCT user_id) as total_users,
                    COUNT(DISTINCT match_id) as total_matches,
                    COUNT(CASE WHEN points_earned > 0 THEN 1 END) as correct_predictions
                FROM predictions
            `);
            
            return {
                ...stats,
                accuracy: stats.total_predictions > 0 
                    ? Math.round((stats.correct_predictions / stats.total_predictions) * 100) 
                    : 0
            };
        } catch (error) {
            console.error('Error getting prediction stats:', error);
            throw error;
        }
    }
}

module.exports = Prediction;
