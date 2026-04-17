'use strict';

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');
const path = require('path');

// Initialize the database on startup
require('./db/database').getDb();

const authRoutes      = require('./routes/auth');
const adminRoutes     = require('./routes/admin');
const converterRoutes = require('./routes/converter');
const { requireAuth } = require('./middleware/auth');

// Middleware for page routes: redirect to login instead of returning JSON
function requirePageAuth(req, res, next) {
  requireAuth(req, res, (err) => {
    if (err) return res.redirect('/');
    next();
  });
}

// Override: if requireAuth called res.status(401) we need to catch that differently.
// Simpler approach: inline the page-auth check.
function pageAuth(req, res, next) {
  const jwt = require('jsonwebtoken');
  const { getDb } = require('./db/database');
  const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-in-production-32chars!!';
  const token = req.cookies?.auth_token;
  if (!token) return res.redirect('/');
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.redirect('/'); }
  const user = getDb().prepare('SELECT id, username, role, status FROM users WHERE id = ?').get(payload.id);
  if (!user || user.status === 'suspended') return res.redirect('/');
  req.user = user;
  next();
}

const app  = express();
// ── CORS: allow the HR Management app (file:// origin) ──────────────
app.use((req, res, next) => {
  const origin = req.headers.origin || 'null';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
// ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

const isProd = process.env.NODE_ENV === 'production';

// Trust the first proxy in front of us (required for correct IP detection on Railway/Render/Fly)
if (isProd) app.set('trust proxy', 1);

// ─── Security headers ────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:              ["'self'"],
      scriptSrc:               ["'self'", "'unsafe-inline'"],
      styleSrc:                ["'self'", "'unsafe-inline'"],
      imgSrc:                  ["'self'", 'data:'],
      connectSrc:              ["'self'"],
      fontSrc:                 ["'self'"],
      objectSrc:               ["'none'"],
      frameSrc:                ["'none'"],
      scriptSrcAttr:           ["'unsafe-inline'"],
      // Only force HTTPS upgrade in production — breaks plain HTTP on localhost
      upgradeInsecureRequests: isProd ? [] : null,
    },
  },
  // Only send HSTS in production — browsers cache this and block HTTP on localhost
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
  crossOriginEmbedderPolicy: false,
}));

// ─── Body parsing ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(cookieParser());

// ─── Rate limiting ───────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,         // 1 minute
  max: 120,
  message: { error: 'Too many requests. Slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', loginLimiter);

// ─── API routes ──────────────────────────────────────────────────────────────
app.use('/api/auth',      authRoutes);
app.use('/api/admin',     adminRoutes);
app.use('/api/convert',   converterRoutes);

// ─── Page routes (protect all pages except login) ────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// Protected pages live in /views (not served statically)
app.get('/converter', pageAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'converter.html'));
});
app.get('/admin', pageAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.redirect('/converter');
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Catch-all: send to login
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ─── Error handler ───────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
