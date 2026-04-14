'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../db/database');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// All admin routes require auth + admin role
router.use(requireAuth, requireAdmin);

function auditLog(actorId, actorName, action, targetId, targetName, detail) {
  getDb().prepare(`
    INSERT INTO audit_log (actor_id, actor_name, action, target_id, target_name, detail)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(actorId, actorName, action, targetId ?? null, targetName ?? null, detail ?? null);
}

// GET /api/admin/users  — list all users
router.get('/users', (req, res) => {
  const users = getDb()
    .prepare(`SELECT id, username, email, role, status, totp_enabled, created_at, last_login
              FROM users ORDER BY created_at DESC`)
    .all();
  res.json({ users });
});

// POST /api/admin/users  — create a new user
router.post('/users', (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  if (typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types' });
  }

  const trimUsername = username.trim();
  const trimEmail = email.trim().toLowerCase();

  if (trimUsername.length < 3 || trimUsername.length > 32) {
    return res.status(400).json({ error: 'Username must be 3–32 characters' });
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(trimUsername)) {
    return res.status(400).json({ error: 'Username may only contain letters, numbers, underscores, hyphens, and dots' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimEmail)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one uppercase letter and one number' });
  }

  const assignedRole = role === 'admin' ? 'admin' : 'user';
  const hash = bcrypt.hashSync(password, 12);

  try {
    const result = getDb().prepare(`
      INSERT INTO users (username, email, password_hash, role, status)
      VALUES (?, ?, ?, ?, 'active')
    `).run(trimUsername, trimEmail, hash, assignedRole);

    auditLog(req.user.id, req.user.username, 'create_user', result.lastInsertRowid, trimUsername,
             `role=${assignedRole}`);

    res.status(201).json({
      message: 'User created successfully',
      user: { id: result.lastInsertRowid, username: trimUsername, email: trimEmail, role: assignedRole, status: 'active' },
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed: users.username')) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    if (err.message.includes('UNIQUE constraint failed: users.email')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    throw err;
  }
});

// DELETE /api/admin/users/:id  — delete a user
router.delete('/users/:id', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  const target = getDb().prepare('SELECT id, username, role FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  // Prevent deleting the last admin
  if (target.role === 'admin') {
    const adminCount = getDb().prepare("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'").get();
    if (adminCount.cnt <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last administrator account' });
    }
  }

  getDb().prepare('DELETE FROM users WHERE id = ?').run(targetId);
  auditLog(req.user.id, req.user.username, 'delete_user', targetId, target.username);

  res.json({ message: `User "${target.username}" deleted` });
});

// PATCH /api/admin/users/:id/suspend  — suspend a user
router.patch('/users/:id/suspend', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'You cannot suspend your own account' });
  }

  const target = getDb().prepare('SELECT id, username, status FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.status === 'suspended') {
    return res.status(400).json({ error: 'User is already suspended' });
  }

  getDb().prepare("UPDATE users SET status = 'suspended' WHERE id = ?").run(targetId);
  auditLog(req.user.id, req.user.username, 'suspend_user', targetId, target.username);

  res.json({ message: `User "${target.username}" suspended` });
});

// PATCH /api/admin/users/:id/activate  — reactivate a suspended user
router.patch('/users/:id/activate', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const target = getDb().prepare('SELECT id, username, status FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.status === 'active') {
    return res.status(400).json({ error: 'User is already active' });
  }

  getDb().prepare("UPDATE users SET status = 'active' WHERE id = ?").run(targetId);
  auditLog(req.user.id, req.user.username, 'activate_user', targetId, target.username);

  res.json({ message: `User "${target.username}" reactivated` });
});

// POST /api/admin/users/:id/reset-password  — admin resets another user's password
router.post('/users/:id/reset-password', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const { newPassword } = req.body;
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (!/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must contain at least one uppercase letter and one number' });
  }

  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const hash = bcrypt.hashSync(newPassword, 12);
  getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, targetId);
  auditLog(req.user.id, req.user.username, 'reset_password', targetId, target.username);

  res.json({ message: `Password for "${target.username}" has been reset` });
});

// POST /api/admin/users/:id/reset-2fa  — admin resets a user's 2FA
router.post('/users/:id/reset-2fa', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const target = getDb().prepare('SELECT id, username, totp_enabled FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (!target.totp_enabled) {
    return res.status(400).json({ error: 'This user does not have 2FA enabled' });
  }

  getDb().prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(targetId);
  auditLog(req.user.id, req.user.username, 'reset_2fa', targetId, target.username);

  res.json({ message: `2FA has been reset for "${target.username}"` });
});

// GET /api/admin/audit-log  — view audit log
router.get('/audit-log', (req, res) => {
  const entries = getDb()
    .prepare(`SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200`)
    .all();
  res.json({ entries });
});

module.exports = router;
