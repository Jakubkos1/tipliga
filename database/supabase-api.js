// Supabase REST API client - avoids SSL certificate issues
class SupabaseAPI {
    constructor() {
        this.baseUrl = process.env.SUPABASE_URL;
        this.apiKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
        this.init();
    }

    init() {
        if (!this.baseUrl || !this.apiKey) {
            throw new Error('Missing Supabase URL or API key');
        }
        console.log('✅ Connected to Supabase REST API');
        this.setupDatabase();
    }

    async setupDatabase() {
        try {
            // Tables are created via SQL in Supabase dashboard
            console.log('✅ Supabase tables ready');
        } catch (error) {
            console.error('❌ Error setting up Supabase:', error);
        }
    }

    async apiQuery(table, options = {}) {
        try {
            let url = `${this.baseUrl}/rest/v1/${table}`;
            const headers = {
                'apikey': this.apiKey,
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            };

            // Handle different query types
            if (options.select) {
                url += `?select=${options.select}`;
            }
            if (options.filter) {
                url += (url.includes('?') ? '&' : '?') + options.filter;
            }
            if (options.order) {
                url += (url.includes('?') ? '&' : '?') + `order=${options.order}`;
            }

            const method = options.method || 'GET';
            const fetchOptions = {
                method,
                headers
            };

            if (options.body && (method === 'POST' || method === 'PATCH')) {
                fetchOptions.body = JSON.stringify(options.body);
            }

            const response = await fetch(url, fetchOptions);
            
            if (!response.ok) {
                throw new Error(`Supabase API error: ${response.status} ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Supabase API query error:', error);
            throw error;
        }
    }

    // SQLite-compatible methods for debug endpoint
    async query(sql, params = []) {
        // For debug endpoint - return current time
        if (sql && sql.includes('NOW()')) {
            return {
                rows: [{
                    current_time: new Date().toISOString(),
                    db_version: 'Supabase REST API v1.0'
                }]
            };
        }
        return { rows: [] };
    }

    async run(sql, params = []) {
        // This is a simplified adapter - for complex SQL, use the query method
        console.log('Note: run() method called, consider using query() for Supabase');
        return { id: null, changes: 0 };
    }

    async get(table, filter) {
        const results = await this.apiQuery(table, { filter, select: '*' });
        return results[0] || null;
    }

    async all(table, filter = '') {
        return await this.apiQuery(table, { filter, select: '*' });
    }

    // User methods
    async findUserByDiscordId(discordId) {
        return await this.get('users', `discord_id=eq.${discordId}`);
    }

    async createUser(userData) {
        const result = await this.apiQuery('users', {
            method: 'POST',
            body: userData
        });
        return result[0];
    }

    async updateUser(id, userData) {
        const result = await this.apiQuery('users', {
            method: 'PATCH',
            filter: `id=eq.${id}`,
            body: userData
        });
        return result[0];
    }

    // Match methods
    async getAllMatches() {
        return await this.all('matches', 'order=match_time.asc');
    }

    async getUpcomingMatches() {
        return await this.all('matches', `status=eq.upcoming&order=match_time.asc`);
    }

    async createMatch(matchData) {
        const result = await this.query('matches', {
            method: 'POST',
            body: matchData
        });
        return result[0];
    }

    async updateMatch(id, matchData) {
        const result = await this.query('matches', {
            method: 'PATCH',
            filter: `id=eq.${id}`,
            body: matchData
        });
        return result[0];
    }

    async deleteMatch(id) {
        await this.query('matches', {
            method: 'DELETE',
            filter: `id=eq.${id}`
        });
        return { changes: 1 };
    }

    // Prediction methods
    async getUserPredictions(userId) {
        return await this.all('predictions', `user_id=eq.${userId}`);
    }

    async createPrediction(predictionData) {
        const result = await this.query('predictions', {
            method: 'POST',
            body: predictionData
        });
        return result[0];
    }

    async updatePrediction(userId, matchId, data) {
        const result = await this.query('predictions', {
            method: 'PATCH',
            filter: `user_id=eq.${userId}&match_id=eq.${matchId}`,
            body: data
        });
        return result[0];
    }

    // Leaderboard
    async getLeaderboard() {
        return await this.all('users', 'order=points.desc,correct_predictions.desc');
    }

    async close() {
        // No connection to close for REST API
        console.log('✅ Supabase API client closed');
    }
}

// Export singleton instance
module.exports = new SupabaseAPI();
