'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { getDb } = require('../db/database');
const {
  signToken, setAuthCookie, clearAuthCookie, requireAuth,
  signPendingToken, verifyPendingToken,
} = require('../middleware/auth');

const router = express.Router();

// POST /api/auth/login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password ||
      typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const trimmedUsername = username.trim();
  if (trimmedUsername.length === 0 || password.length === 0) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = getDb()
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(trimmedUsername);

  // Constant-time comparison to avoid timing attacks
  const hash = user?.password_hash || '$2a$12$invalidhashfortimingpurposesonly00000000000000000000';
  const match = bcrypt.compareSync(password, hash);

  if (!user || !match) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'Your account has been suspended. Contact the administrator.' });
  }

  // If 2FA is enabled, issue a short-lived pending token instead of logging in
  if (user.totp_enabled) {
    const pendingToken = signPendingToken(user.id);
    return res.json({ requires2fa: true, pendingToken });
  }

  // No 2FA — log in normally
  getDb().prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);

  const token = signToken(user);
  setAuthCookie(res, token);

  res.json({
    message: 'Login successful',
    user: { id: user.id, username: user.username, role: user.role },
  });
});

// POST /api/auth/2fa/verify  — complete login when 2FA is required
router.post('/2fa/verify', (req, res) => {
  const { pendingToken, code } = req.body;

  if (!pendingToken || !code ||
      typeof pendingToken !== 'string' || typeof code !== 'string') {
    return res.status(400).json({ error: 'Pending token and code are required' });
  }

  let payload;
  try {
    payload = verifyPendingToken(pendingToken);
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  const user = getDb()
    .prepare('SELECT * FROM users WHERE id = ?')
    .get(payload.id);

  if (!user || !user.totp_enabled || !user.totp_secret) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'Your account has been suspended.' });
  }

  const isValid = authenticator.verify({ token: code.replace(/\s/g, ''), secret: user.totp_secret });
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid code. Please try again.' });
  }

  getDb().prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);

  const token = signToken(user);
  setAuthCookie(res, token);

  res.json({
    message: 'Login successful',
    user: { id: user.id, username: user.username, role: user.role },
  });
});

// POST /api/auth/logout
router.post('/logout', requireAuth, (req, res) => {
  clearAuthCookie(res);
  res.json({ message: 'Logged out' });
});

// GET /api/auth/me  — check current session
router.get('/me', requireAuth, (req, res) => {
  const full = getDb()
    .prepare('SELECT id, username, role, status, totp_enabled FROM users WHERE id = ?')
    .get(req.user.id);
  res.json({ user: full });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword ||
      typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'Both current and new password are required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (!/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'New password must contain at least one uppercase letter and one number' });
  }

  const user = getDb()
    .prepare('SELECT password_hash FROM users WHERE id = ?')
    .get(req.user.id);

  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const newHash = bcrypt.hashSync(newPassword, 12);
  getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);

  getDb().prepare(`
    INSERT INTO audit_log (actor_id, actor_name, action, target_id, target_name)
    VALUES (?, ?, 'change_own_password', ?, ?)
  `).run(req.user.id, req.user.username, req.user.id, req.user.username);

  res.json({ message: 'Password changed successfully' });
});

// POST /api/auth/2fa/setup  — generate a new TOTP secret and QR code (not enabled yet)
router.post('/2fa/setup', requireAuth, async (req, res) => {
  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(req.user.username, 'Unit Converter', secret);

  // Store the secret temporarily (totp_enabled stays 0 until confirmed)
  getDb()
    .prepare('UPDATE users SET totp_secret = ? WHERE id = ?')
    .run(secret, req.user.id);

  try {
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
    res.json({ qrCode: qrDataUrl, secret, otpauthUrl });
  } catch {
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// POST /api/auth/2fa/confirm  — verify first code and activate 2FA
router.post('/2fa/confirm', requireAuth, (req, res) => {
  const { code } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Code is required' });
  }

  const user = getDb()
    .prepare('SELECT totp_secret, totp_enabled FROM users WHERE id = ?')
    .get(req.user.id);

  if (!user.totp_secret) {
    return res.status(400).json({ error: 'No 2FA setup in progress. Start setup first.' });
  }
  if (user.totp_enabled) {
    return res.status(400).json({ error: '2FA is already enabled' });
  }

  const isValid = authenticator.verify({ token: code.replace(/\s/g, ''), secret: user.totp_secret });
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid code. Make sure your authenticator app time is correct.' });
  }

  getDb()
    .prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?')
    .run(req.user.id);

  getDb().prepare(`
    INSERT INTO audit_log (actor_id, actor_name, action, target_id, target_name)
    VALUES (?, ?, 'enable_2fa', ?, ?)
  `).run(req.user.id, req.user.username, req.user.id, req.user.username);

  res.json({ message: '2FA enabled successfully' });
});

// POST /api/auth/2fa/disable  — disable 2FA (requires current password)
router.post('/2fa/disable', requireAuth, (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required to disable 2FA' });
  }

  const user = getDb()
    .prepare('SELECT password_hash, totp_enabled FROM users WHERE id = ?')
    .get(req.user.id);

  if (!user.totp_enabled) {
    return res.status(400).json({ error: '2FA is not currently enabled' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  getDb()
    .prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?')
    .run(req.user.id);

  getDb().prepare(`
    INSERT INTO audit_log (actor_id, actor_name, action, target_id, target_name)
    VALUES (?, ?, 'disable_2fa', ?, ?)
  `).run(req.user.id, req.user.username, req.user.id, req.user.username);

  res.json({ message: '2FA has been disabled' });
});

module.exports = router;
