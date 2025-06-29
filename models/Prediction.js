const db = require('../database/db');

class Prediction {
    static async create(predictionData) {
        try {
            const { userId, matchId, predictedWinner } = predictionData;

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API - check if prediction exists first
                const existingPredictions = await db.apiQuery('predictions', {
                    filter: `user_id=eq.${userId}&match_id=eq.${matchId}`,
                    select: '*'
                });

                if (existingPredictions.length > 0) {
                    // Update existing prediction
                    const updated = await db.apiQuery('predictions', {
                        method: 'PATCH',
                        filter: `user_id=eq.${userId}&match_id=eq.${matchId}`,
                        body: {
                            predicted_winner: predictedWinner,
                            updated_at: new Date().toISOString()
                        }
                    });
                    return updated[0];
                } else {
                    // Create new prediction
                    const created = await db.apiQuery('predictions', {
                        method: 'POST',
                        body: {
                            user_id: userId,
                            match_id: matchId,
                            predicted_winner: predictedWinner,
                            updated_at: new Date().toISOString()
                        }
                    });
                    return created[0];
                }
            } else {
                // Using SQLite
                const result = await db.run(`
                    INSERT OR REPLACE INTO predictions (user_id, match_id, predicted_winner, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                `, [userId, matchId, predictedWinner]);

                return await this.findById(result.id);
            }
        } catch (error) {
            console.error('Error creating/updating prediction:', error);
            throw error;
        }
    }

    static async findById(id) {
        try {
            // Handle null/undefined ID
            if (!id) {
                return null;
            }

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                const predictions = await db.apiQuery('predictions', {
                    filter: `id=eq.${id}`,
                    select: '*'
                });
                return predictions[0] || null;
            } else {
                // Using SQLite
                const prediction = await db.get('SELECT * FROM predictions WHERE id = ?', [id]);
                return prediction;
            }
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
                        status: match?.status,
                        deleted: match?.deleted
                    };
                }));

                // Filter out predictions for deleted matches and sort by match_time DESC
                return predictionsWithMatches
                    .filter(prediction => !prediction.deleted)
                    .sort((a, b) => new Date(b.match_time) - new Date(a.match_time));
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
                    WHERE p.user_id = ? AND (m.deleted = 0 OR m.deleted IS NULL)
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
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API - calculate stats in JavaScript
                const predictions = await db.apiQuery('predictions', {
                    select: '*'
                });
                const matches = await db.apiQuery('matches', { select: '*' });

                // Filter out predictions for deleted matches
                const validPredictions = predictions.filter(prediction => {
                    const match = matches.find(m => m.id === prediction.match_id);
                    return match && !match.deleted;
                });

                const total_predictions = validPredictions.length;
                const total_users = new Set(validPredictions.map(p => p.user_id)).size;
                const total_matches = new Set(validPredictions.map(p => p.match_id)).size;
                const correct_predictions = validPredictions.filter(p => p.points_earned > 0).length;

                return {
                    total_predictions,
                    total_users,
                    total_matches,
                    correct_predictions,
                    accuracy: total_predictions > 0
                        ? Math.round((correct_predictions / total_predictions) * 100)
                        : 0
                };
            } else {
                // Using SQLite
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
            }
        } catch (error) {
            console.error('Error getting prediction stats:', error);
            throw error;
        }
    }
}

module.exports = Prediction;
