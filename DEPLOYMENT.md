# TipLiga v2.0 - Deployment Guide

## 🚀 Quick Deploy to Vercel (Recommended)

### 1. Push to GitHub
1. Create new repository on GitHub
2. Push your code:
```bash
git init
git add .
git commit -m "Initial commit - TipLiga v2.0"
git branch -M main
git remote add origin https://github.com/yourusername/tipliga-v2.git
git push -u origin main
```

### 2. Prepare Discord App
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create new application or use existing
3. Go to OAuth2 → General
4. Add redirect URL: `https://your-app-name.vercel.app/auth/discord/callback`
5. Copy Client ID and Client Secret

### 3. Deploy to Vercel
1. Go to [Vercel.com](https://vercel.com)
2. Sign up with GitHub
3. Click "New Project"
4. Import your GitHub repository
5. Vercel will auto-detect and deploy

### 4. Set Environment Variables
In Vercel dashboard, go to Settings → Environment Variables and add:
```
DISCORD_CLIENT_ID=your_client_id_here
DISCORD_CLIENT_SECRET=your_client_secret_here
SESSION_SECRET=random_string_here
NODE_ENV=production
APP_URL=https://your-app-name.vercel.app
ADMIN_IDS=311028583948746753
```

### 5. Update Discord Redirect URL
Update your Discord app's redirect URL to match your Vercel domain.

## 🌐 Alternative: Deploy to Render

### 1. Go to [Render.com](https://render.com)
2. Connect GitHub repository
3. Choose "Web Service"
4. Set build command: `npm install`
5. Set start command: `npm start`
6. Add environment variables (same as above)

## 🔧 Local Development

1. Copy `.env.example` to `.env`
2. Fill in your Discord credentials
3. Run `npm install`
4. Run `npm start`
5. Visit `http://localhost:3200`

## 📝 Notes

- **Database**: Uses in-memory SQLite on Vercel (data resets on deployment)
- **Local Development**: Uses file-based SQLite (data persists)
- **App sleeps** on free hosting after inactivity
- **First request** after sleep takes ~30 seconds to wake up
- **Vercel** provides generous free tier for personal projects

## ⚠️ Important: In-Memory Database

On Vercel, the app uses an in-memory database, which means:
- **Data resets** when the app restarts or redeploys
- **Perfect for testing** and demonstrations
- **For production**, consider using a hosted database like:
  - Vercel Postgres
  - PlanetScale
  - Supabase
  - Railway PostgreSQL

## 🎮 Admin Setup

Add your Discord User ID to ADMIN_IDS environment variable to get admin access.
