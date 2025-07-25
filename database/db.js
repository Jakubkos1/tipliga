const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Use Supabase REST API to avoid SSL certificate issues
const useSupabaseAPI = !!(process.env.SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

if (useSupabaseAPI) {
    console.log('🚀 Using Supabase REST API (no SSL issues)');
    module.exports = require('./supabase-api');
} else {
    console.log('🗄️ Using SQLite database (local development)');

class Database {
    constructor() {
        this.db = null;
        this.init();
    }

    init() {
        // Use file database for persistence (Vercel allows /tmp directory)
        const isProduction = process.env.NODE_ENV === 'production';
        const dbPath = isProduction ? '/tmp/tipliga.db' : path.join(__dirname, 'tipliga.db');

        console.log(`🗄️ Using ${isProduction ? 'temporary file' : 'local file'} database: ${dbPath}`);

        this.db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('❌ Error opening database:', err.message);
                process.exit(1);
            } else {
                console.log('✅ Connected to SQLite database');
                this.setupDatabase();
            }
        });
    }

    setupDatabase() {
        // Read and execute schema
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');
        
        this.db.exec(schema, (err) => {
            if (err) {
                console.error('❌ Error setting up database:', err.message);
            } else {
                console.log('✅ Database schema initialized');
                this.runMigrations();
            }
        });
    }

    runMigrations() {
        // Add role column to users table if it doesn't exist
        this.db.run(`
            ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'
        `, (err) => {
            if (err && !err.message.includes('duplicate column name')) {
                console.error('❌ Migration error:', err.message);
            } else if (!err) {
                console.log('✅ Added role column to users table');
            }
        });

        // Clean up test matches
        this.db.run(`
            DELETE FROM matches WHERE team_a IN ('Real Madrid', 'Manchester United', 'Bayern Munich', 'PSG')
        `, (err) => {
            if (err) {
                console.error('❌ Error cleaning test matches:', err.message);
            } else {
                console.log('✅ Cleaned up test matches');
            }
        });
    }

    // Promisify database methods for easier async/await usage
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve({ id: this.lastID, changes: this.changes });
                }
            });
        });
    }

    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    close() {
        return new Promise((resolve, reject) => {
            this.db.close((err) => {
                if (err) {
                    reject(err);
                } else {
                    console.log('✅ Database connection closed');
                    resolve();
                }
            });
        });
    }
}

// Export singleton instance
module.exports = new Database();

} // End of SQLite class - only used in development
