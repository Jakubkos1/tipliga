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
                    WHERE m.deleted = 0 OR m.deleted IS NULL
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

    // Helper function to get current time in Prague timezone
    static getPragueTime() {
        // Get current time and convert to Prague timezone
        const now = new Date();
        const pragueTime = new Date(now.toLocaleString("en-US", {timeZone: "Europe/Prague"}));
        return pragueTime;
    }

    // Helper function to parse match time - assume it's already in Prague time
    static parseMatchTimeAsPrague(matchTime) {
        // Simply parse the match time as-is, assuming it's Prague time
        // The admin creates matches in their local time (Prague), so no conversion needed
        return new Date(matchTime);
    }

    static isMatchLocked(matchTime, status) {
        if (status !== 'upcoming') return true;

        // Simple approach: adjust the server time to match the timezone issue
        const now = new Date();
        const matchDate = new Date(matchTime);

        // The issue is that match times are stored as if they were UTC, but they're actually Prague time
        // So we need to subtract 2 hours from the match time to get the correct comparison
        // Prague is UTC+2 in summer, so match time needs to be adjusted
        const pragueOffset = 2 * 60 * 60 * 1000; // 2 hours in milliseconds (summer time)
        const adjustedMatchTime = matchDate.getTime() - pragueOffset;
        const adjustedMatchDate = new Date(adjustedMatchTime);

        const lockTime = 60 * 60 * 1000; // 1 hour before match
        const timeUntilMatch = adjustedMatchDate - now;
        const minutesUntilMatch = Math.round(timeUntilMatch / (1000 * 60));

        // Debug timezone info with more details
        console.log('🕐 Timezone Debug (Offset Corrected):');
        console.log('  Server time (UTC):', now.toISOString());
        console.log('  Server time (Prague):', now.toLocaleString('cs-CZ', {timeZone: 'Europe/Prague'}));
        console.log('  Match time (input):', matchTime);
        console.log('  Match time (original):', matchDate.toISOString());
        console.log('  Match time (adjusted -2h):', adjustedMatchDate.toISOString());
        console.log('  Match time (adjusted Prague):', adjustedMatchDate.toLocaleString('cs-CZ', {timeZone: 'Europe/Prague'}));
        console.log('  Time difference (ms):', timeUntilMatch);
        console.log('  Time until match (minutes):', minutesUntilMatch);
        console.log('  Lock time (minutes):', lockTime / (1000 * 60));
        console.log('  Is locked:', timeUntilMatch <= lockTime);
        console.log('  Should be locked if minutes <=', lockTime / (1000 * 60));

        return timeUntilMatch <= lockTime;
    }

    static canEvaluateMatch(matchTime, status) {
        // Can evaluate if match has started (not just finished)
        if (status === 'finished') return true; // Already evaluated
        if (status !== 'upcoming') return false; // Invalid status

        // Apply the same timezone correction as in isMatchLocked
        const now = new Date();
        const matchDate = new Date(matchTime);

        // Apply 2-hour offset correction for Prague timezone
        const pragueOffset = 2 * 60 * 60 * 1000; // 2 hours in milliseconds (summer time)
        const adjustedMatchTime = matchDate.getTime() - pragueOffset;
        const adjustedMatchDate = new Date(adjustedMatchTime);

        console.log('🔍 Match Evaluation Timezone Debug:');
        console.log('  Server time (UTC):', now.toISOString());
        console.log('  Match time (input):', matchTime);
        console.log('  Match time (original):', matchDate.toISOString());
        console.log('  Match time (adjusted -2h):', adjustedMatchDate.toISOString());
        console.log('  Can evaluate:', now >= adjustedMatchDate);

        // Can evaluate if match has started (current time >= adjusted match time)
        return now >= adjustedMatchDate;
    }

    static getMatchStatus(matchTime, currentStatus) {
        const now = new Date();
        const matchDate = new Date(matchTime);

        // Apply 2-hour offset correction for Prague timezone
        const pragueOffset = 2 * 60 * 60 * 1000; // 2 hours in milliseconds (summer time)
        const adjustedMatchTime = matchDate.getTime() - pragueOffset;
        const adjustedMatchDate = new Date(adjustedMatchTime);
        const oneHourBefore = adjustedMatchDate.getTime() - (60 * 60 * 1000);

        if (currentStatus === 'finished') return 'finished';

        if (now.getTime() >= adjustedMatchDate.getTime()) {
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

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                await db.apiQuery('matches', {
                    method: 'PATCH',
                    filter: `id=eq.${matchId}`,
                    body: {
                        team_a: teamA,
                        team_b: teamB,
                        match_time: matchTime,
                        updated_at: new Date().toISOString()
                    }
                });
            } else {
                // Using SQLite
                await db.run(
                    'UPDATE matches SET team_a = ?, team_b = ?, match_time = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [teamA, teamB, matchTime, matchId]
                );
            }

            return await this.findById(matchId);
        } catch (error) {
            console.error('Error updating match:', error);
            throw error;
        }
    }

    static async softDelete(matchId) {
        try {
            console.log(`🗑️ Starting soft delete for match ID: ${matchId}`);

            // Check if using Supabase API or SQLite
            if (db.apiQuery) {
                // Using Supabase API
                console.log('🔄 Using Supabase API for soft delete');

                try {
                    const result = await db.apiQuery('matches', {
                        method: 'PATCH',
                        filter: `id=eq.${matchId}`,
                        body: {
                            deleted: true,
                            deleted_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        }
                    });
                    console.log('✅ Supabase soft delete result:', result);

                    // Verify the delete worked by checking the match
                    await this.debugMatchState(matchId);

                } catch (softDeleteError) {
                    console.error('❌ Soft delete failed, trying hard delete as fallback:', softDeleteError);

                    // If soft delete fails (e.g., deleted column doesn't exist), do hard delete
                    console.log('🔄 Attempting hard delete as fallback...');
                    await this.hardDelete(matchId);
                }

            } else {
                // Using SQLite
                console.log('🔄 Using SQLite for soft delete');
                await db.run(
                    'UPDATE matches SET deleted = 1, deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [matchId]
                );
            }

            console.log(`🗑️ Match ${matchId} deleted (kept in database for backup)`);
            return true;
        } catch (error) {
            console.error('❌ Error deleting match:', error);
            throw error;
        }
    }

    static async hardDelete(matchId) {
        try {
            console.log(`🗑️ Hard deleting match ID: ${matchId}`);

            if (db.apiQuery) {
                // Using Supabase API - DELETE request
                const result = await db.apiQuery('matches', {
                    method: 'DELETE',
                    filter: `id=eq.${matchId}`
                });
                console.log('✅ Supabase hard delete result:', result);
            } else {
                // Using SQLite
                await db.run('DELETE FROM matches WHERE id = ?', [matchId]);
            }

            console.log(`🗑️ Match ${matchId} permanently deleted from database`);
            return true;
        } catch (error) {
            console.error('❌ Error hard deleting match:', error);
            throw error;
        }
    }

    static async debugMatchState(matchId) {
        try {
            console.log(`🔍 Checking match ${matchId} state after delete...`);

            // Get match without any filters to see actual state
            const allMatches = await db.apiQuery('matches', {
                filter: `id=eq.${matchId}`,
                select: '*'
            });

            if (allMatches.length > 0) {
                const match = allMatches[0];
                console.log('📊 Match state:', {
                    id: match.id,
                    teams: `${match.team_a} vs ${match.team_b}`,
                    deleted: match.deleted,
                    deleted_at: match.deleted_at,
                    hasDeletedColumn: 'deleted' in match
                });
            } else {
                console.log('❌ Match not found in database');
            }
        } catch (error) {
            console.error('❌ Error checking match state:', error);
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
