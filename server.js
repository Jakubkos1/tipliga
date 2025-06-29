require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const rateLimit = require('express-rate-limit');
const path = require('path');

// Import models and database
const User = require('./models/User');
const Match = require('./models/Match');
const Prediction = require('./models/Prediction');
const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Vercel
app.set('trust proxy', 1);

// Rate limiting - More generous for normal browsing
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // limit each IP to 1000 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware
// Temporarily disable rate limiting for debugging
// app.use(limiter);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: `${process.env.APP_URL || `http://localhost:${PORT}`}/auth/discord/callback`,
    scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('🔍 Discord profile data:', JSON.stringify(profile, null, 2));

        // Discord profile structure: profile.id, profile.username, profile.avatar, profile.discriminator
        const discordUser = {
            id: profile.id,
            username: profile.username,
            discriminator: profile.discriminator,
            avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null
        };

        console.log('🔍 Processed Discord user:', discordUser);

        const user = await User.updateOrCreate(discordUser);
        console.log('🔍 Database user:', user);

        return done(null, user);
    } catch (error) {
        console.error('❌ Discord OAuth error:', error);
        console.error('❌ Error stack:', error.stack);
        console.error('❌ Error details:', {
            message: error.message,
            code: error.code,
            errno: error.errno
        });
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Helper middleware
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
};

const isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && process.env.ADMIN_IDS.split(',').includes(req.user.discord_id)) {
        return next();
    }
    res.status(403).send('Access denied');
};

// Helper function to check if user is admin
const checkIsAdmin = (user) => {
    return user && process.env.ADMIN_IDS.split(',').includes(user.discord_id);
};

// Helper function to check if user is moderator (can manage matches but not users)
const checkIsModerator = (user) => {
    if (!user) return false;
    return user.role === 'moderator';
};

// Helper function to check if user has admin or moderator privileges
const checkCanManageMatches = (user) => {
    return checkIsAdmin(user) || checkIsModerator(user);
};

// Test route for debugging user session
app.get('/debug-user', (req, res) => {
    res.json({
        isAuthenticated: req.isAuthenticated(),
        user: req.user,
        session: req.session
    });
});

// Debug route to check database connection
app.get('/debug-db', async (req, res) => {
    try {
        const isPostgres = !!(process.env.DATABASE_URL || process.env.POSTGRES_URL);
        const dbType = isPostgres ? 'PostgreSQL (Supabase)' : 'SQLite (Local)';

        // Test database connection
        let testResult;
        if (isPostgres) {
            testResult = await db.query('SELECT NOW() as current_time, version() as db_version');
        } else {
            testResult = await db.get('SELECT datetime("now") as current_time');
        }

        res.json({
            database_type: dbType,
            environment: process.env.NODE_ENV,
            has_database_url: !!(process.env.DATABASE_URL || process.env.POSTGRES_URL),
            database_url_preview: (process.env.DATABASE_URL || process.env.POSTGRES_URL) ? (process.env.DATABASE_URL || process.env.POSTGRES_URL).substring(0, 20) + '...' : 'Not set',
            connection_test: testResult,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            error: 'Database connection failed',
            message: error.message,
            database_type: process.env.DATABASE_URL ? 'PostgreSQL (Failed)' : 'SQLite (Failed)'
        });
    }
});

// Routes
app.get('/', async (req, res) => {
    try {
        const matches = await Match.getUpcoming();
        
        // Get user predictions if logged in
        let userPredictions = {};
        if (req.user) {
            const predictions = await Prediction.getUserPredictions(req.user.id);
            userPredictions = predictions.reduce((acc, pred) => {
                acc[pred.match_id] = pred.predicted_winner;
                return acc;
            }, {});
        }
        
        console.log('🏠 Rendering homepage for user:', req.user);
        console.log('🔐 Is admin:', checkIsAdmin(req.user));

        res.render('index', {
            user: req.user,
            matches,
            userPredictions,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user)
        });
    } catch (error) {
        console.error('Error loading homepage:', error);
        res.status(500).render('error', { message: 'Error loading matches' });
    }
});

// Authentication routes
app.get('/auth/discord', (req, res, next) => {
    console.log('🔐 Discord OAuth initiated');
    passport.authenticate('discord')(req, res, next);
});

app.get('/auth/discord/callback',
    (req, res, next) => {
        console.log('🔄 Discord OAuth callback received');
        console.log('Query params:', req.query);
        next();
    },
    passport.authenticate('discord', {
        failureRedirect: '/?error=auth_failed',
        failureMessage: true
    }),
    (req, res) => {
        try {
            console.log('✅ Discord OAuth successful for user:', req.user ? req.user.username : 'undefined user');
            console.log('🔍 User object:', req.user);
            res.redirect('/?success=logged_in');
        } catch (error) {
            console.error('❌ Error in Discord callback:', error);
            res.redirect('/?error=callback_failed');
        }
    }
);

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// Prediction routes
app.post('/predict', isAuthenticated, async (req, res) => {
    try {
        const { matchId, winner } = req.body;
        
        if (!matchId || !winner) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Check if match exists and is not locked
        const match = await Match.findById(matchId);
        if (!match) {
            return res.status(404).json({ error: 'Match not found' });
        }
        
        if (Match.isMatchLocked(match.match_time, match.status)) {
            return res.status(400).json({ error: 'Betting is closed for this match' });
        }
        
        // Create or update prediction
        await Prediction.create({
            userId: req.user.id,
            matchId: parseInt(matchId),
            predictedWinner: winner
        });
        
        res.json({ success: true, message: 'Prediction saved successfully!' });
    } catch (error) {
        console.error('Error saving prediction:', error);
        res.status(500).json({ error: 'Error saving prediction' });
    }
});

// API route for getting match statistics
app.get('/api/match/:id/stats', async (req, res) => {
    try {
        const { id } = req.params;

        // Get match details
        const match = await Match.findById(id);
        if (!match) {
            return res.status(404).json({ success: false, error: 'Match not found' });
        }

        // Get predictions for this match
        let predictions = [];
        if (db.apiQuery) {
            // Using Supabase API
            predictions = await db.apiQuery('predictions', {
                filter: `match_id=eq.${id}`,
                select: '*'
            });
        } else {
            // Using SQLite
            predictions = await db.all('SELECT * FROM predictions WHERE match_id = ?', [id]);
        }

        // Calculate stats
        const totalPredictions = predictions.length;
        const votesTeamA = predictions.filter(p => p.predicted_winner === match.team_a).length;
        const votesTeamB = predictions.filter(p => p.predicted_winner === match.team_b).length;

        res.json({
            success: true,
            total_predictions: totalPredictions,
            votes_team_a: votesTeamA,
            votes_team_b: votesTeamB,
            percent_team_a: totalPredictions > 0 ? Math.round((votesTeamA / totalPredictions) * 100) : 0,
            percent_team_b: totalPredictions > 0 ? Math.round((votesTeamB / totalPredictions) * 100) : 0
        });
    } catch (error) {
        console.error('Error getting match stats:', error);
        res.status(500).json({ success: false, error: 'Error getting match stats' });
    }
});

// Public leaderboard route
app.get('/leaderboard', async (req, res) => {
    try {
        const leaderboard = await User.getLeaderboard();
        const stats = await Prediction.getStats();

        res.render('leaderboard', {
            user: req.user,
            leaderboard,
            stats,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user)
        });
    } catch (error) {
        console.error('Error loading leaderboard:', error);
        res.status(500).render('error', { message: 'Error loading leaderboard' });
    }
});

// User Management Routes (Admin only)
app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const users = await User.getAllUsers();

        res.render('admin-users', {
            user: req.user,
            users,
            isAdmin: true,
            success: req.query.success,
            error: req.query.error
        });
    } catch (error) {
        console.error('Error loading users:', error);
        res.redirect('/admin?error=Chyba při načítání uživatelů');
    }
});

app.post('/admin/users/:id/role', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        // Prevent admin from changing their own role
        if (parseInt(id) === req.user.id) {
            return res.redirect('/admin/users?error=Nemůžete změnit svou vlastní roli');
        }

        await User.updateUserRole(id, role);
        console.log(`✅ Admin ${req.user.username} changed user ${id} role to ${role}`);

        res.redirect('/admin/users?success=Role byla úspěšně změněna');
    } catch (error) {
        console.error('Error updating user role:', error);
        res.redirect('/admin/users?error=Chyba při změně role');
    }
});

app.post('/admin/users/:id/reset-stats', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        await User.resetUserStats(id);

        if (parseInt(id) === req.user.id) {
            console.log(`✅ Admin ${req.user.username} reset their own stats`);
            res.redirect('/admin/users?success=Your statistics have been reset successfully');
        } else {
            console.log(`✅ Admin ${req.user.username} reset stats for user ${id}`);
            res.redirect('/admin/users?success=User statistics have been reset successfully');
        }
    } catch (error) {
        console.error('Error resetting user stats:', error);
        res.redirect('/admin/users?error=Error resetting statistics');
    }
});

app.post('/admin/users/:id/delete', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent admin from deleting themselves
        if (parseInt(id) === req.user.id) {
            return res.redirect('/admin/users?error=Nemůžete smazat sám sebe');
        }

        await User.deleteUser(id);
        console.log(`✅ Admin ${req.user.username} deleted user ${id}`);

        res.redirect('/admin/users?success=Uživatel byl úspěšně smazán');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.redirect('/admin/users?error=Chyba při mazání uživatele');
    }
});

// Admin routes - accessible to moderators for match management
app.get('/admin', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        const matches = await Match.getAll();
        const stats = await Prediction.getStats();
        const leaderboard = await User.getLeaderboard();

        res.render('admin-simple', {
            user: req.user,
            matches,
            stats,
            leaderboard,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user),
            success: req.query.success,
            error: req.query.error
        });
    } catch (error) {
        console.error('Error loading admin panel:', error);
        res.status(500).render('error', { message: 'Error loading admin panel' });
    }
});

// Admin form routes (simple POST forms) - accessible to moderators
app.post('/admin/matches', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        const { teamA, teamB, matchTime } = req.body;

        if (!teamA || !teamB || !matchTime) {
            return res.redirect('/admin?error=Missing required fields');
        }

        // Validate that match time is in the future
        const matchDate = new Date(matchTime);
        const now = new Date();

        if (matchDate <= now) {
            return res.redirect('/admin?error=Match time must be in the future');
        }

        const match = await Match.create({ teamA, teamB, matchTime });
        console.log(`✅ ${req.user.username} created match: ${teamA} vs ${teamB} at ${matchTime}`);

        res.redirect('/admin?success=Match created successfully!');
    } catch (error) {
        console.error('Error creating match:', error);
        res.redirect('/admin?error=Error creating match');
    }
});

app.post('/admin/matches/:id/result', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        const { id } = req.params;
        const { winner } = req.body;

        if (!winner) {
            return res.redirect('/admin?error=Winner is required');
        }

        const match = await Match.updateResult(id, winner);
        console.log(`✅ Admin ${req.user.username} set result: ${match.team_a} vs ${match.team_b} - Winner: ${winner}`);

        res.redirect('/admin?success=Výsledek byl úspěšně nastaven!');
    } catch (error) {
        console.error('Error updating match result:', error);
        res.redirect('/admin?error=Chyba při nastavování výsledku');
    }
});

app.post('/admin/matches/:id/edit', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        const { id } = req.params;
        const { teamA, teamB, matchTime } = req.body;

        if (!teamA || !teamB || !matchTime) {
            return res.redirect('/admin?error=Missing required fields');
        }

        // Validate that match time is in the future
        const matchDate = new Date(matchTime);
        const now = new Date();

        if (matchDate <= now) {
            return res.redirect('/admin?error=Match time must be in the future');
        }

        const match = await Match.update(id, { teamA, teamB, matchTime });
        console.log(`✅ ${req.user.username} updated match: ${teamA} vs ${teamB} at ${matchTime}`);

        res.redirect('/admin?success=Match updated successfully!');
    } catch (error) {
        console.error('Error updating match:', error);
        res.redirect('/admin?error=Error updating match');
    }
});

app.post('/admin/matches/:id/delete', isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        await Match.delete(id);
        console.log(`✅ Admin ${req.user.username} deleted match ID: ${id}`);

        res.redirect('/admin?success=Zápas byl úspěšně smazán!');
    } catch (error) {
        console.error('Error deleting match:', error);
        res.redirect('/admin?error=Chyba při mazání zápasu');
    }
});

app.put('/admin/matches/:id', isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { teamA, teamB, matchTime } = req.body;

        if (!teamA || !teamB || !matchTime) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const match = await Match.update(id, { teamA, teamB, matchTime });
        console.log(`✅ Admin ${req.user.username} updated match: ${teamA} vs ${teamB}`);

        res.json({ success: true, match });
    } catch (error) {
        console.error('Error updating match:', error);
        res.status(500).json({ error: 'Error updating match' });
    }
});

app.delete('/admin/matches/:id', isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        await Match.delete(id);
        console.log(`✅ Admin ${req.user.username} deleted match ID: ${id}`);

        res.json({ success: true, message: 'Match deleted successfully' });
    } catch (error) {
        console.error('Error deleting match:', error);
        res.status(500).json({ error: 'Error deleting match' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 TipLiga v2.0 server running on http://localhost:${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});
