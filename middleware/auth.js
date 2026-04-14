'use strict';

const jwt = require('jsonwebtoken');
const { getDb } = require('../db/database');

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  // Warn loudly if no secret is set in production
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET environment variable must be set in production');
  }
  return 'dev-only-secret-change-in-production-32chars!!';
})();

const COOKIE_NAME = 'auth_token';
const TOKEN_TTL_SECONDS = 8 * 60 * 60; // 8 hours
const PENDING_2FA_TTL = 5 * 60;         // 5 minutes

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL_SECONDS }
  );
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: TOKEN_TTL_SECONDS * 1000,
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict' });
}

// Middleware: require a valid JWT cookie
function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    clearAuthCookie(res);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  // Verify the user still exists and is active
  const user = getDb()
    .prepare('SELECT id, username, role, status FROM users WHERE id = ?')
    .get(payload.id);

  if (!user) {
    clearAuthCookie(res);
    return res.status(401).json({ error: 'Account not found' });
  }
  if (user.status === 'suspended') {
    clearAuthCookie(res);
    return res.status(403).json({ error: 'Your account has been suspended. Contact the administrator.' });
  }

  req.user = user;
  next();
}

// Middleware: require admin role (must follow requireAuth)
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Issue a short-lived token for the 2FA verification step
function signPendingToken(userId) {
  return jwt.sign({ id: userId, pending2fa: true }, JWT_SECRET, { expiresIn: PENDING_2FA_TTL });
}

// Verify a pending-2FA token; throws if invalid/expired
function verifyPendingToken(token) {
  const payload = jwt.verify(token, JWT_SECRET);
  if (!payload.pending2fa) throw new Error('Not a pending-2FA token');
  return payload;
}

module.exports = { signToken, setAuthCookie, clearAuthCookie, requireAuth, requireAdmin, signPendingToken, verifyPendingToken, COOKIE_NAME };
