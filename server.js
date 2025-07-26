require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

// Security utility functions
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[<>'"&]/g, (match) => {
        const entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        };
        return entities[match];
    });
};

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
// Enable rate limiting for security
app.use(limiter);

// Security headers (bez X-XSS-Protection která blokuje Alpine.js)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    // Odstraněno X-XSS-Protection - blokuje Alpine.js
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create uploads directory if it doesn't exist (only in local environment)
const uploadsDir = path.join(__dirname, 'public', 'uploads');
const isVercel = process.env.VERCEL || process.env.NODE_ENV === 'production';

if (!isVercel) {
    // Only create directory in local development
    if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
    }
}

// Configure multer for file uploads
let upload;

if (isVercel) {
    // In serverless environment, disable file uploads and show error
    upload = multer({
        storage: multer.memoryStorage(),
        limits: { fileSize: 1 }, // Effectively disable
        fileFilter: function (req, file, cb) {
            cb(new Error('File uploads are not supported in serverless environment. Please use image URLs instead.'), false);
        }
    });
} else {
    // Local development - normal file upload
    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, uploadsDir);
        },
        filename: function (req, file, cb) {
            // Generate unique filename with timestamp
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const ext = path.extname(file.originalname);
            cb(null, 'article-' + uniqueSuffix + ext);
        }
    });

    upload = multer({
        storage: storage,
        limits: {
            fileSize: 5 * 1024 * 1024 // 5MB limit
        },
        fileFilter: function (req, file, cb) {
            // Check file type
            if (file.mimetype.startsWith('image/')) {
                cb(null, true);
            } else {
                cb(new Error('Only image files are allowed!'), false);
            }
        }
    });
}

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
if (!process.env.SESSION_SECRET) {
    console.error('❌ SESSION_SECRET environment variable is required for security');
    process.exit(1);
}

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiration on each request
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true, // Prevent XSS attacks
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (more conservative)
        sameSite: 'lax' // CSRF protection
    }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Debug middleware to track session issues (disabled in production for security)
app.use((req, res, next) => {
    if (process.env.NODE_ENV !== 'production' && (req.originalUrl.includes('/tipliga') || req.originalUrl.includes('/auth'))) {
        console.log(`🔍 Session Debug - URL: ${req.originalUrl}`);
        console.log(`🔍 User: ${req.user ? req.user.username : 'Not logged in'}`);
        // Don't log session ID for security
    }
    next();
});

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: `${process.env.APP_URL || `http://localhost:${PORT}`}/auth/discord/callback`,
    scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Only log in development for security
        if (process.env.NODE_ENV !== 'production') {
            console.log('🔍 Discord profile data:', JSON.stringify(profile, null, 2));
        }

        // Discord profile structure: profile.id, profile.username, profile.avatar, profile.discriminator
        const discordUser = {
            id: profile.id,
            username: profile.username,
            discriminator: profile.discriminator,
            avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null
        };

        if (process.env.NODE_ENV !== 'production') {
            console.log('🔍 Processed Discord user:', discordUser);
        }

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
// Main homepage route - redirect to TipLiga (articles disabled for now)
app.get('/', async (req, res) => {
    try {
        console.log('🏠 Main homepage accessed - redirecting to TipLiga');
        console.log('🔐 User:', req.user ? req.user.username : 'Not logged in');

        // Redirect to TipLiga since we're focusing only on that for now
        res.redirect('/tipliga');
    } catch (error) {
        console.error('Error redirecting to TipLiga:', error);
        res.status(500).render('error', { message: 'Error loading page' });
    }
});

// Articles listing page - DISABLED (redirect to TipLiga)
app.get('/articles', async (req, res) => {
    try {
        console.log('📰 Articles page accessed - redirecting to TipLiga (articles disabled)');
        res.redirect('/tipliga');
    } catch (error) {
        console.error('Error redirecting from articles:', error);
        res.status(500).render('error', { message: 'Error loading page' });
    }
});

// Individual article reading page - DISABLED (redirect to TipLiga)
app.get('/articles/:id', async (req, res) => {
    try {
        console.log('📰 Article accessed:', req.params.id, '- redirecting to TipLiga (articles disabled)');
        res.redirect('/tipliga');
    } catch (error) {
        console.error('Error redirecting from article:', error);
        res.status(500).render('error', { message: 'Error loading page' });
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

// Session heartbeat endpoint to keep sessions alive
app.post('/api/heartbeat', (req, res) => {
    if (req.user && req.session) {
        req.session.touch();
        res.json({ status: 'ok', user: req.user.username });
    } else {
        res.status(401).json({ status: 'unauthorized' });
    }
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
        let { matchId, winner } = req.body;

        if (!matchId || !winner) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate and sanitize inputs
        matchId = parseInt(matchId);
        if (isNaN(matchId) || matchId <= 0) {
            return res.status(400).json({ error: 'Invalid match ID' });
        }

        winner = sanitizeInput(winner.toString().trim());
        if (winner.length === 0 || winner.length > 50) {
            return res.status(400).json({ error: 'Invalid winner name' });
        }

        // Check if match exists and is not locked
        const match = await Match.findById(matchId);
        if (!match) {
            return res.status(404).json({ error: 'Match not found' });
        }

        // Validate that winner is one of the teams
        if (winner !== match.team_a && winner !== match.team_b) {
            return res.status(400).json({ error: 'Winner must be one of the competing teams' });
        }

        if (Match.isMatchLocked(match.match_time, match.status)) {
            return res.status(400).json({ error: 'Betting is closed for this match' });
        }

        // Create or update prediction
        await Prediction.create({
            userId: req.user.id,
            matchId: matchId,
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

// OBS Overlay route - zobrazí live statistiky pro streaming
app.get('/obs/overlay/:matchId?', async (req, res) => {
    try {
        const { matchId } = req.params;

        // Pokud není zadáno matchId, najdi nejnovější upcoming zápas
        let match;
        if (matchId) {
            match = await Match.findById(matchId);
        } else {
            const matches = await Match.getAll();
            match = matches.find(m => m.status === 'upcoming') || matches[0];
        }

        if (!match) {
            return res.render('obs-overlay', {
                match: null,
                error: 'Žádný zápas nenalezen'
            });
        }

        res.render('obs-overlay', {
            match: match,
            error: null
        });
    } catch (error) {
        console.error('Error loading OBS overlay:', error);
        res.render('obs-overlay', {
            match: null,
            error: 'Chyba při načítání overlay'
        });
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

// Admin article management routes - DISABLED (focusing on TipLiga only)
/*
app.get('/admin/articles', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        // Get all articles (including unpublished) for admin management
        let articles = [];
        try {
            articles = await Article.getAll(50); // Get latest 50 articles
        } catch (error) {
            console.log('⚠️ Articles table not available yet:', error.message);
            articles = [];
        }

        res.render('admin-articles', {
            user: req.user,
            articles: articles,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user),
            isSuperAdmin: checkIsSuperAdmin(req.user)
        });
    } catch (error) {
        console.error('Error loading admin articles:', error);
        res.status(500).render('error', { message: 'Error loading articles' });
    }
});
*/

/*
app.get('/admin/articles/new', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, (req, res) => {
    res.render('admin-article-form', {
        user: req.user,
        article: null, // New article
        isEdit: false,
        isAdmin: checkIsAdmin(req.user),
        isModerator: checkIsModerator(req.user),
        isSuperAdmin: checkIsSuperAdmin(req.user)
    });
});

app.get('/admin/articles/:id/edit', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        const article = await Article.findById(req.params.id);
        if (!article) {
            return res.status(404).render('error', { message: 'Article not found' });
        }

        res.render('admin-article-form', {
            user: req.user,
            article: article,
            isEdit: true,
            isAdmin: checkIsAdmin(req.user),
            isModerator: checkIsModerator(req.user),
            isSuperAdmin: checkIsSuperAdmin(req.user)
        });
    } catch (error) {
        console.error('Error loading article for edit:', error);
        res.status(500).render('error', { message: 'Error loading article' });
    }
});
*/

/*
app.post('/admin/articles', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, (req, res, next) => {
    // Handle file upload with error handling
    upload.single('image_file')(req, res, function (err) {
        if (err) {
            console.log('File upload error (expected in production):', err.message);
            // Continue without file upload in production
            next();
        } else {
            next();
        }
    });
}, async (req, res) => {
    try {
        const { title, content, excerpt, image_url, published } = req.body;

        // Determine image URL - prioritize uploaded file over URL
        let finalImageUrl = image_url;
        if (req.file && !isVercel) {
            finalImageUrl = `/uploads/${req.file.filename}`;
        }

        const articleData = {
            title,
            content,
            excerpt,
            image_url: finalImageUrl,
            author_id: req.user.id,
            published: published === 'on' ? 1 : 0
        };

        await Article.create(articleData);
        console.log(`✅ ${req.user.username} created article: ${title}`);
        res.redirect('/admin/articles?success=Article created successfully');
    } catch (error) {
        console.error('Error creating article:', error);
        // Clean up uploaded file if article creation failed
        if (req.file && !isVercel) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting uploaded file:', err);
            });
        }
        res.redirect('/admin/articles?error=Error creating article');
    }
});
*/

/*
app.post('/admin/articles/:id/edit', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, (req, res, next) => {
    // Handle file upload with error handling
    upload.single('image_file')(req, res, function (err) {
        if (err) {
            console.log('File upload error (expected in production):', err.message);
            // Continue without file upload in production
            next();
        } else {
            next();
        }
    });
}, async (req, res) => {
    try {
        const { title, content, excerpt, image_url, published } = req.body;

        // Get current article to preserve existing image if no new one uploaded
        const currentArticle = await Article.findById(req.params.id);

        // Determine image URL - prioritize uploaded file over URL, then existing image
        let finalImageUrl = currentArticle.image_url; // Keep existing by default
        if (req.file && !isVercel) {
            finalImageUrl = `/uploads/${req.file.filename}`;
            // Delete old uploaded file if it exists and is in uploads folder
            if (currentArticle.image_url && currentArticle.image_url.startsWith('/uploads/')) {
                const oldFilePath = path.join(__dirname, 'public', currentArticle.image_url);
                fs.unlink(oldFilePath, (err) => {
                    if (err && err.code !== 'ENOENT') console.error('Error deleting old file:', err);
                });
            }
        } else if (image_url && image_url !== currentArticle.image_url) {
            finalImageUrl = image_url;
        }

        const articleData = {
            title,
            content,
            excerpt,
            image_url: finalImageUrl,
            published: published === 'on' ? 1 : 0
        };

        await Article.update(req.params.id, articleData);
        console.log(`✅ ${req.user.username} updated article: ${title}`);
        res.redirect('/admin/articles?success=Article updated successfully');
    } catch (error) {
        console.error('Error updating article:', error);
        // Clean up uploaded file if article update failed
        if (req.file && !isVercel) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting uploaded file:', err);
            });
        }
        res.redirect('/admin/articles?error=Error updating article');
    }
});

app.post('/admin/articles/:id/delete', isAuthenticated, (req, res, next) => {
    if (checkCanManageMatches(req.user)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}, async (req, res) => {
    try {
        await Article.softDelete(req.params.id);
        res.redirect('/admin/articles?success=Article deleted successfully');
    } catch (error) {
        console.error('Error deleting article:', error);
        res.redirect('/admin/articles?error=Error deleting article');
    }
});
*/

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
        let { teamA, teamB, matchTime } = req.body;

        if (!teamA || !teamB || !matchTime) {
            return res.redirect('/admin?error=Missing required fields');
        }

        // Trim team names (sanitizace odstraněna - způsobovala problémy s Alpine.js)
        teamA = teamA.trim();
        teamB = teamB.trim();

        // Validate team names length and content
        if (teamA.length > 50 || teamB.length > 50) {
            return res.redirect('/admin?error=Team names must be 50 characters or less');
        }

        if (teamA === teamB) {
            return res.redirect('/admin?error=Team names must be different');
        }

        // Validate that match time is in the future
        const matchDate = new Date(matchTime);
        const now = new Date();

        if (isNaN(matchDate.getTime())) {
            return res.redirect('/admin?error=Invalid match time format');
        }

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
