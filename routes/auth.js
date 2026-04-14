'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../db/database');
const { signToken, setAuthCookie, clearAuthCookie, requireAuth } = require('../middleware/auth');

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

  // Use a constant-time comparison to avoid timing attacks
  const hash = user?.password_hash || '$2a$12$invalidhashfortimingpurposesonly00000000000000000000';
  const match = bcrypt.compareSync(password, hash);

  if (!user || !match) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'Your account has been suspended. Contact the administrator.' });
  }

  // Update last_login
  getDb()
    .prepare('UPDATE users SET last_login = datetime(\'now\') WHERE id = ?')
    .run(user.id);

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
  res.json({ user: req.user });
});

// POST /api/auth/change-password  — change own password
router.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword ||
      typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'Both current and new password are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }

  // Enforce at least one uppercase, one number
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
  getDb()
    .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(newHash, req.user.id);

  // Log the action
  getDb().prepare(`
    INSERT INTO audit_log (actor_id, actor_name, action, target_id, target_name)
    VALUES (?, ?, 'change_own_password', ?, ?)
  `).run(req.user.id, req.user.username, req.user.id, req.user.username);

  res.json({ message: 'Password changed successfully' });
});

module.exports = router;
