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
const Article = require('./models/Article');
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

// Add request logging for debugging
app.use((req, res, next) => {
    if (req.method === 'DELETE' || req.originalUrl.includes('/admin/matches')) {
        console.log(`📝 Request: ${req.method} ${req.originalUrl}`);
    }
    next();
});

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
    if (req.isAuthenticated() && checkIsAdmin(req.user)) {
        return next();
    }
    res.status(403).send('Access denied');
};

const isSuperAdmin = (req, res, next) => {
    if (req.isAuthenticated() && checkIsSuperAdmin(req.user)) {
        return next();
    }
    res.status(403).send('Access denied - Super Admin required');
};

// Helper function to check if user is a super admin (hardcoded in ADMIN_IDS)
const checkIsSuperAdmin = (user) => {
    return user && process.env.ADMIN_IDS && process.env.ADMIN_IDS.split(',').includes(user.discord_id);
};

// Helper function to check if user is admin (database role OR hardcoded)
const checkIsAdmin = (user) => {
    if (!user) return false;

    // Check if user has admin role in database OR is in the hardcoded admin list
    const hasAdminRole = user.role === 'admin';
    const isHardcodedAdmin = checkIsSuperAdmin(user);

    return hasAdminRole || isHardcodedAdmin;
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



// Routes
// Main homepage route (articles page)
app.get('/', async (req, res) => {
    try {
        console.log('🏠 Main homepage accessed');
        console.log('🔐 User:', req.user ? req.user.username : 'Not logged in');

        // Get published articles for homepage
        const articles = await Article.getPublished(10); // Get latest 10 articles

        res.render('homepage', {
            user: req.user,
            articles: articles,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user)
        });
    } catch (error) {
        console.error('Error loading homepage:', error);
        res.status(500).render('error', { message: 'Error loading homepage' });
    }
});

// TipLiga route (moved from homepage)
app.get('/tipliga', async (req, res) => {
    try {
        console.log('🏆 TipLiga accessed');
        console.log('🔐 User:', req.user ? req.user.username : 'Not logged in');

        const matches = await Match.getUpcoming();

        // Add locking information to each match
        const matchesWithLocking = matches.map(match => ({
            ...match,
            is_locked: Match.isMatchLocked(match.match_time, match.status)
        }));

        // Get user predictions if logged in
        let userPredictions = {};
        if (req.user) {
            const predictions = await Prediction.getUserPredictions(req.user.id);
            userPredictions = predictions.reduce((acc, pred) => {
                acc[pred.match_id] = pred.predicted_winner;
                return acc;
            }, {});
        }

        console.log('🏆 Rendering TipLiga for user:', req.user);
        console.log('🔐 Is admin:', checkIsAdmin(req.user));

        res.render('index', {
            user: req.user,
            matches: matchesWithLocking,
            userPredictions,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user)
        });
    } catch (error) {
        console.error('Error loading TipLiga:', error);
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

// User prediction history page
app.get('/tipliga/my-predictions', isAuthenticated, async (req, res) => {
    try {
        const predictions = await Prediction.getUserPredictions(req.user.id);

        // Sort predictions by match time (newest first)
        const sortedPredictions = predictions.sort((a, b) =>
            new Date(b.match_time) - new Date(a.match_time)
        );

        res.render('my-predictions', {
            user: req.user,
            predictions: sortedPredictions,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user)
        });
    } catch (error) {
        console.error('Error loading user predictions:', error);
        res.status(500).render('error', { message: 'Error loading your predictions' });
    }
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
app.get('/tipliga/leaderboard', async (req, res) => {
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
            isSuperAdmin: checkIsSuperAdmin(req.user),
            success: req.query.success,
            error: req.query.error
        });
    } catch (error) {
        console.error('Error loading users:', error);
        res.redirect('/admin?error=Error loading users');
    }
});

app.post('/admin/users/:id/role', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        // Prevent admin from changing their own role
        if (parseInt(id) === req.user.id) {
            return res.redirect('/admin/users?error=You cannot change your own role');
        }

        // Get the target user to check their current role
        const targetUser = await User.findById(id);
        if (!targetUser) {
            return res.redirect('/admin/users?error=User not found');
        }

        // Only super admins can manage admin roles
        const isSuperAdminUser = checkIsSuperAdmin(req.user);
        const targetIsAdmin = targetUser.role === 'admin' || checkIsSuperAdmin(targetUser);
        const requestingAdminRole = role === 'admin';

        if (!isSuperAdminUser && (targetIsAdmin || requestingAdminRole)) {
            return res.redirect('/admin/users?error=Only super admins can manage admin roles');
        }

        await User.updateUserRole(id, role);
        console.log(`✅ ${isSuperAdminUser ? 'Super Admin' : 'Admin'} ${req.user.username} changed user ${id} role to ${role}`);

        res.redirect('/admin/users?success=Role was successfully changed');
    } catch (error) {
        console.error('Error updating user role:', error);
        res.redirect('/admin/users?error=Error changing role');
    }
});

app.post('/admin/users/:id/reset-stats', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Get the target user to check their role (unless it's self-reset)
        let targetUser = null;
        if (parseInt(id) !== req.user.id) {
            targetUser = await User.findById(id);
            if (!targetUser) {
                return res.redirect('/admin/users?error=User not found');
            }

            // Only super admins can reset admin stats (except their own)
            const isSuperAdminUser = checkIsSuperAdmin(req.user);
            const targetIsAdmin = targetUser.role === 'admin' || checkIsSuperAdmin(targetUser);

            if (!isSuperAdminUser && targetIsAdmin) {
                return res.redirect('/admin/users?error=Only super admins can reset admin statistics');
            }
        }

        await User.resetUserStats(id);

        if (parseInt(id) === req.user.id) {
            console.log(`✅ Admin ${req.user.username} reset their own stats`);
            res.redirect('/admin/users?success=Your statistics have been reset successfully');
        } else {
            const isSuperAdminUser = checkIsSuperAdmin(req.user);
            console.log(`✅ ${isSuperAdminUser ? 'Super Admin' : 'Admin'} ${req.user.username} reset stats for user ${id} (role: ${targetUser.role})`);
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
            return res.redirect('/admin/users?error=You cannot delete yourself');
        }

        // Get the target user to check their role
        const targetUser = await User.findById(id);
        if (!targetUser) {
            return res.redirect('/admin/users?error=User not found');
        }

        // Only super admins can delete admin accounts
        const isSuperAdminUser = checkIsSuperAdmin(req.user);
        const targetIsAdmin = targetUser.role === 'admin' || checkIsSuperAdmin(targetUser);

        if (!isSuperAdminUser && targetIsAdmin) {
            return res.redirect('/admin/users?error=Only super admins can delete admin accounts');
        }

        await User.deleteUser(id);
        console.log(`✅ ${isSuperAdminUser ? 'Super Admin' : 'Admin'} ${req.user.username} deleted user ${id} (role: ${targetUser.role})`);

        res.redirect('/admin/users?success=User was successfully deleted');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.redirect('/admin/users?error=Error deleting user');
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

        // Check if match exists and can be evaluated
        const match = await Match.findById(id);
        if (!match) {
            return res.redirect('/admin?error=Match not found');
        }

        // Check if match can be evaluated (has started)
        if (!Match.canEvaluateMatch(match.match_time, match.status)) {
            return res.redirect('/admin?error=Match cannot be evaluated yet - wait until match has started');
        }

        // Validate winner is one of the teams
        if (winner !== match.team_a && winner !== match.team_b) {
            return res.redirect('/admin?error=Winner must be one of the competing teams');
        }

        const updatedMatch = await Match.updateResult(id, winner);
        console.log(`✅ Admin ${req.user.username} set result: ${updatedMatch.team_a} vs ${updatedMatch.team_b} - Winner: ${winner}`);

        res.redirect('/admin?success=Match result set successfully! Points awarded to correct predictions.');
    } catch (error) {
        console.error('Error updating match result:', error);
        res.redirect('/admin?error=Error setting match result');
    }
});

// Reset match result route
app.post('/admin/matches/:id/reset', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`🔄 Reset result request received for match ID: ${id} by user: ${req.user?.username}`);

        // Check if match exists
        const match = await Match.findById(id);
        if (!match) {
            return res.status(404).json({ success: false, error: 'Match not found' });
        }

        // Reset the match result
        const resetMatch = await Match.resetResult(id);
        console.log(`✅ Admin ${req.user.username} reset result for match: ${resetMatch.team_a} vs ${resetMatch.team_b} (ID: ${id})`);

        res.redirect('/admin?success=Match result reset successfully! You can now set a new winner.');
    } catch (error) {
        console.error('Error resetting match result:', error);
        res.redirect('/admin?error=Error resetting match result');
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

// Add middleware to log all DELETE requests
app.use('/admin/matches', (req, res, next) => {
    if (req.method === 'DELETE') {
        console.log(`🔍 DELETE request intercepted: ${req.method} ${req.originalUrl}`);
        console.log(`🔍 Request params:`, req.params);
        console.log(`🔍 User:`, req.user?.username || 'Not authenticated');
    }
    next();
});

// Handle the POST route that the frontend is actually using
app.post('/admin/matches/:id/delete', isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`🗑️ POST DELETE request received for match ID: ${id} by user: ${req.user?.username}`);

        // Check if match exists and is not already deleted
        const match = await Match.findById(id);
        if (!match) {
            console.log(`❌ Match ${id} not found`);
            return res.redirect('/admin?error=Match not found');
        }

        console.log(`🔍 Found match to delete: ${match.team_a} vs ${match.team_b}`);

        // Use soft delete - mark as deleted but keep in database
        console.log(`🔄 Using soft delete (marking as deleted) for match ${id}...`);
        try {
            const softDeleteResult = await db.apiQuery('matches', {
                method: 'PATCH',
                filter: `id=eq.${id}`,
                body: {
                    deleted: true,
                    deleted_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }
            });
            console.log(`✅ Soft delete result:`, softDeleteResult);
            console.log(`✅ Admin ${req.user.username} soft deleted match: ${match.team_a} vs ${match.team_b} (ID: ${id}) - kept in database for backup`);
        } catch (softDeleteError) {
            console.error(`❌ Soft delete failed:`, softDeleteError);
            throw softDeleteError;
        }

        // Redirect back to admin panel with success message
        res.redirect('/admin?success=Match deleted successfully (kept in database for backup)!');
    } catch (error) {
        console.error('❌ Error deleting match:', error);
        res.redirect('/admin?error=Error deleting match');
    }
});

// Keep the original DELETE route as well for completeness
app.delete('/admin/matches/:id', isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`🗑️ DELETE request received for match ID: ${id} by user: ${req.user?.username}`);

        // Check if match exists and is not already deleted
        const match = await Match.findById(id);
        if (!match) {
            console.log(`❌ Match ${id} not found`);
            return res.status(404).json({ error: 'Match not found' });
        }

        console.log(`🔍 Found match to delete: ${match.team_a} vs ${match.team_b}`);

        // Use direct Supabase API DELETE call
        console.log(`🔄 Using direct Supabase API DELETE for match ${id}...`);
        try {
            const directResult = await db.apiQuery('matches', {
                method: 'DELETE',
                filter: `id=eq.${id}`
            });
            console.log(`✅ Direct delete result:`, directResult);
            console.log(`✅ Admin ${req.user.username} deleted match: ${match.team_a} vs ${match.team_b} (ID: ${id})`);
        } catch (directError) {
            console.error(`❌ Direct delete failed:`, directError);
            throw directError;
        }

        res.json({
            success: true,
            message: 'Match deleted successfully'
        });
    } catch (error) {
        console.error('❌ Error deleting match:', error);
        res.status(500).json({ error: 'Error deleting match' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 TipLiga v2.0 server running on http://localhost:${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});
