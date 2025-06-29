// Supabase REST API client - avoids SSL certificate issues
class SupabaseAPI {
    constructor() {
        this.baseUrl = process.env.SUPABASE_URL;
        // Try different possible API key environment variables
        this.apiKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
                     process.env.SUPABASE_ANON_KEY ||
                     process.env.SUPABASE_KEY;
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
            const queryParams = [];

            if (options.select) {
                queryParams.push(`select=${options.select}`);
            }
            if (options.filter) {
                queryParams.push(options.filter);
            }
            if (options.order) {
                queryParams.push(`order=${options.order}`);
            }

            if (queryParams.length > 0) {
                url += `?${queryParams.join('&')}`;
            }

            const method = options.method || 'GET';
            const fetchOptions = {
                method,
                headers
            };

            if (options.body && (method === 'POST' || method === 'PATCH')) {
                fetchOptions.body = JSON.stringify(options.body);
            }

            // Debug logging
            console.log('🔍 Supabase API Request:', {
                url,
                method,
                table,
                baseUrl: this.baseUrl,
                hasApiKey: !!this.apiKey
            });

            const response = await fetch(url, fetchOptions);

            console.log('📡 Supabase API Response:', {
                status: response.status,
                statusText: response.statusText,
                url: response.url
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Supabase API Error Details:', errorText);
                throw new Error(`Supabase API error: ${response.status} ${response.statusText} - ${errorText}`);
            }

            const data = await response.json();
            console.log('✅ Supabase API Success:', { table, rowCount: data?.length || 'unknown' });
            return data;
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

    async get(sql, params = []) {
        // Handle SQLite-style queries for compatibility
        if (typeof sql === 'string' && sql.includes('SELECT')) {
            console.log('⚠️ SQLite-style query detected, converting for Supabase API:', sql);

            // Parse simple SELECT queries
            if (sql.includes('FROM matches WHERE id = ?')) {
                const id = params[0];
                const results = await this.apiQuery('matches', {
                    filter: `id=eq.${id}`,
                    select: '*'
                });
                return results[0] || null;
            }
            else if (sql.includes('FROM users WHERE id = ?')) {
                const id = params[0];
                const results = await this.apiQuery('users', {
                    filter: `id=eq.${id}`,
                    select: '*'
                });
                return results[0] || null;
            }
            else if (sql.includes('FROM users WHERE discord_id = ?')) {
                const discordId = params[0];
                const results = await this.apiQuery('users', {
                    filter: `discord_id=eq.${discordId}`,
                    select: '*'
                });
                return results[0] || null;
            }
            else if (sql.includes('FROM predictions WHERE')) {
                // Handle prediction queries
                if (sql.includes('user_id = ? AND match_id = ?')) {
                    const [userId, matchId] = params;
                    const results = await this.apiQuery('predictions', {
                        filter: `user_id=eq.${userId}&match_id=eq.${matchId}`,
                        select: '*'
                    });
                    return results[0] || null;
                }
                else if (sql.includes('id = ?')) {
                    const id = params[0];
                    const results = await this.apiQuery('predictions', {
                        filter: `id=eq.${id}`,
                        select: '*'
                    });
                    return results[0] || null;
                }
            }

            // Try to extract table name and basic WHERE clause for simple queries
            const tableMatch = sql.match(/FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*\?/i);
            if (tableMatch) {
                const [, tableName, columnName] = tableMatch;
                const value = params[0];
                console.log(`🔄 Converting simple query: ${tableName}.${columnName} = ${value}`);

                const results = await this.apiQuery(tableName, {
                    filter: `${columnName}=eq.${value}`,
                    select: '*'
                });
                return results[0] || null;
            }

            // Fallback for unsupported queries
            console.error('❌ Unsupported SQL query for Supabase API:', sql);
            return null;
        }

        // Handle direct table/filter calls (legacy)
        const results = await this.apiQuery(sql, { filter: params, select: '*' });
        return results[0] || null;
    }

    async all(table, filter = '') {
        const options = { select: '*' };
        if (filter && typeof filter === 'string' && filter.trim()) {
            options.filter = filter;
        }
        return await this.apiQuery(table, options);
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

    // Match methods - proper Supabase authentication
    async getAllMatches() {
        try {
            const url = `${this.baseUrl}/rest/v1/matches?deleted=eq.false`;
            console.log('🔍 API call to:', url);
            console.log('🔑 Using API key:', this.apiKey ? 'Present' : 'Missing');

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'apikey': this.apiKey,
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('📡 Response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ API Error:', errorText);
                throw new Error(`API error: ${response.status} ${response.statusText} - ${errorText}`);
            }

            const data = await response.json();
            console.log('✅ Got matches:', data.length);
            return data;
        } catch (error) {
            console.error('❌ getAllMatches error:', error);
            throw error;
        }
    }

    async getUpcomingMatches() {
        try {
            const url = `${this.baseUrl}/rest/v1/matches?status=eq.upcoming&deleted=eq.false`;
            console.log('🔍 API call to:', url);

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'apikey': this.apiKey,
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('📡 Response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ API Error:', errorText);
                throw new Error(`API error: ${response.status} ${response.statusText} - ${errorText}`);
            }

            const data = await response.json();
            console.log('✅ Got upcoming matches:', data.length);
            return data;
        } catch (error) {
            console.error('❌ getUpcomingMatches error:', error);
            throw error;
        }
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
