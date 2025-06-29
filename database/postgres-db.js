const { Pool } = require('pg');

class PostgresDatabase {
    constructor() {
        this.pool = null;
        this.init();
    }

    init() {
        // Use DATABASE_URL, POSTGRES_URL, or POSTGRES_URL_NON_POOLING from Supabase
        const connectionString = process.env.DATABASE_URL ||
                                process.env.POSTGRES_URL_NON_POOLING ||
                                process.env.POSTGRES_URL;

        // Configure SSL for production (Vercel + Supabase)
        const sslConfig = process.env.NODE_ENV === 'production' ? {
            rejectUnauthorized: false,
            require: true
        } : false;

        this.pool = new Pool({
            connectionString: connectionString,
            ssl: sslConfig
        });

        console.log('✅ Connected to PostgreSQL database');
        this.setupDatabase();
    }

    async setupDatabase() {
        try {
            // Create tables if they don't exist
            await this.createTables();
            console.log('✅ Database schema initialized');
        } catch (error) {
            console.error('❌ Error setting up database:', error);
        }
    }

    async createTables() {
        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                discord_id VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) NOT NULL,
                avatar_url TEXT,
                role VARCHAR(50) DEFAULT 'user',
                total_predictions INTEGER DEFAULT 0,
                correct_predictions INTEGER DEFAULT 0,
                points INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        const createMatchesTable = `
            CREATE TABLE IF NOT EXISTS matches (
                id SERIAL PRIMARY KEY,
                team_a VARCHAR(255) NOT NULL,
                team_b VARCHAR(255) NOT NULL,
                match_time TIMESTAMP NOT NULL,
                status VARCHAR(50) DEFAULT 'upcoming',
                winner VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        const createPredictionsTable = `
            CREATE TABLE IF NOT EXISTS predictions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                match_id INTEGER REFERENCES matches(id) ON DELETE CASCADE,
                predicted_winner VARCHAR(255) NOT NULL,
                is_correct BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, match_id)
            );
        `;

        await this.query(createUsersTable);
        await this.query(createMatchesTable);
        await this.query(createPredictionsTable);
    }

    // Promisify database methods for easier async/await usage
    async query(text, params = []) {
        try {
            const result = await this.pool.query(text, params);
            return result;
        } catch (error) {
            console.error('Database query error:', error);
            throw error;
        }
    }

    async run(sql, params = []) {
        const result = await this.query(sql, params);
        return {
            id: result.rows[0]?.id,
            changes: result.rowCount
        };
    }

    async get(sql, params = []) {
        const result = await this.query(sql, params);
        return result.rows[0];
    }

    async all(sql, params = []) {
        const result = await this.query(sql, params);
        return result.rows;
    }

    async close() {
        if (this.pool) {
            await this.pool.end();
            console.log('✅ Database connection closed');
        }
    }
}

// Export singleton instance
module.exports = new PostgresDatabase();
