const db = require('../database/db');

class Match {
    static async getAll() {
        try {
            // Check if using Supabase API or SQLite
            if (db.getAllMatches) {
                // Using Supabase API
                const matches = await db.getAllMatches();

                // Get predictions for each match to calculate votes
                const matchesWithVotes = await Promise.all(matches.map(async (match) => {
                    const predictions = await db.getUserPredictions ?
                        await db.apiQuery('predictions', { filter: `match_id=eq.${match.id}`, select: '*' }) :
                        [];

                    const votes_team_a = predictions.filter(p => p.predicted_winner === match.team_a).length;
                    const votes_team_b = predictions.filter(p => p.predicted_winner === match.team_b).length;
                    const total_predictions = predictions.length;

                    return {
                        ...match,
                        total_predictions,
                        votes_team_a,
                        votes_team_b,
                        percent_team_a: total_predictions > 0 ? Math.round((votes_team_a / total_predictions) * 100) : 0,
                        percent_team_b: total_predictions > 0 ? Math.round((votes_team_b / total_predictions) * 100) : 0,
                        is_locked: this.isMatchLocked(match.match_time, match.status)
                    };
                }));

                return matchesWithVotes;
            } else {
                // Using SQLite
                const matches = await db.all(`
                    SELECT
                        m.*,
                        COUNT(p.id) as total_predictions,
                        COUNT(CASE WHEN p.predicted_winner = m.team_a THEN 1 END) as votes_team_a,
                        COUNT(CASE WHEN p.predicted_winner = m.team_b THEN 1 END) as votes_team_b
                    FROM matches m
                    LEFT JOIN predictions p ON m.id = p.match_id
                    GROUP BY m.id
                    ORDER BY m.match_time ASC
                `);

                // Calculate percentages
                return matches.map(match => ({
                    ...match,
                    percent_team_a: match.total_predictions > 0
                        ? Math.round((match.votes_team_a / match.total_predictions) * 100)
                        : 0,
                    percent_team_b: match.total_predictions > 0
                        ? Math.round((match.votes_team_b / match.total_predictions) * 100)
                        : 0,
                    is_locked: this.isMatchLocked(match.match_time, match.status)
                }));
            }
        } catch (error) {
            console.error('Error getting all matches:', error);
            throw error;
        }
    }

    static async getUpcoming() {
        try {
            const matches = await this.getAll();
            return matches.filter(match => match.status === 'upcoming');
        } catch (error) {
            console.error('Error getting upcoming matches:', error);
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
                const matches = await db.apiQuery('matches', {
                    filter: `id=eq.${id}`,
                    select: '*'
                });
                return matches[0] || null;
            } else {
                // Using SQLite
                const match = await db.get('SELECT * FROM matches WHERE id = ?', [id]);
                return match;
            }
        } catch (error) {
            console.error('Error finding match by ID:', error);
            throw error;
        }
    }

    static async create(matchData) {
        try {
            const { teamA, teamB, matchTime } = matchData;

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                const created = await db.apiQuery('matches', {
                    method: 'POST',
                    body: {
                        team_a: teamA,
                        team_b: teamB,
                        match_time: matchTime,
                        status: 'upcoming',
                        created_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    }
                });
                return created[0];
            } else {
                // Using SQLite
                const result = await db.run(
                    'INSERT INTO matches (team_a, team_b, match_time) VALUES (?, ?, ?)',
                    [teamA, teamB, matchTime]
                );

                return await this.findById(result.id);
            }
        } catch (error) {
            console.error('Error creating match:', error);
            throw error;
        }
    }

    static async updateResult(matchId, winner) {
        try {
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                await db.apiQuery('matches', {
                    method: 'PATCH',
                    filter: `id=eq.${matchId}`,
                    body: {
                        winner: winner,
                        status: 'finished',
                        updated_at: new Date().toISOString()
                    }
                });
            } else {
                // Using SQLite
                await db.run(
                    'UPDATE matches SET winner = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [winner, 'finished', matchId]
                );
            }

            // Award points to correct predictions
            await this.awardPoints(matchId, winner);

            return await this.findById(matchId);
        } catch (error) {
            console.error('Error updating match result:', error);
            throw error;
        }
    }

    static async awardPoints(matchId, winner) {
        try {
            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                await db.apiQuery('predictions', {
                    method: 'PATCH',
                    filter: `match_id=eq.${matchId}&predicted_winner=eq.${winner}`,
                    body: {
                        points_earned: 1
                    }
                });
            } else {
                // Using SQLite
                await db.run(
                    'UPDATE predictions SET points_earned = 1 WHERE match_id = ? AND predicted_winner = ?',
                    [matchId, winner]
                );
            }
        } catch (error) {
            console.error('Error awarding points:', error);
            throw error;
        }
    }

    static isMatchLocked(matchTime, status) {
        if (status !== 'upcoming') return true;

        const now = new Date();
        const matchDate = new Date(matchTime);
        const lockTime = 60 * 60 * 1000; // 1 hour before match

        return (matchDate - now) <= lockTime;
    }

    static canEvaluateMatch(matchTime, status) {
        // Can evaluate if match has started (not just finished)
        if (status === 'finished') return true; // Already evaluated
        if (status !== 'upcoming') return false; // Invalid status

        const now = new Date();
        const matchDate = new Date(matchTime);

        // Can evaluate if match has started (current time >= match time)
        return now >= matchDate;
    }

    static getMatchStatus(matchTime, currentStatus) {
        const now = new Date();
        const matchDate = new Date(matchTime);
        const oneHourBefore = matchDate.getTime() - (60 * 60 * 1000);

        if (currentStatus === 'finished') return 'finished';

        if (now.getTime() >= matchDate.getTime()) {
            return 'live'; // Match has started
        } else if (now.getTime() >= oneHourBefore) {
            return 'locked'; // Betting closed
        } else {
            return 'upcoming'; // Still accepting bets
        }
    }

    static async update(matchId, matchData) {
        try {
            const { teamA, teamB, matchTime } = matchData;
            await db.run(
                'UPDATE matches SET team_a = ?, team_b = ?, match_time = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [teamA, teamB, matchTime, matchId]
            );

            return await this.findById(matchId);
        } catch (error) {
            console.error('Error updating match:', error);
            throw error;
        }
    }

    static async delete(matchId) {
        try {
            // First delete all predictions for this match
            await db.run('DELETE FROM predictions WHERE match_id = ?', [matchId]);

            // Then delete the match
            await db.run('DELETE FROM matches WHERE id = ?', [matchId]);
        } catch (error) {
            console.error('Error deleting match:', error);
            throw error;
        }
    }

    static async getUserPredictions(userId) {
        try {
            const predictions = await db.all(`
                SELECT
                    m.*,
                    p.predicted_winner,
                    p.points_earned,
                    p.created_at as prediction_time
                FROM matches m
                JOIN predictions p ON m.id = p.match_id
                WHERE p.user_id = ?
                ORDER BY m.match_time DESC
            `, [userId]);

            return predictions;
        } catch (error) {
            console.error('Error getting user predictions:', error);
            throw error;
        }
    }
}

module.exports = Match;
