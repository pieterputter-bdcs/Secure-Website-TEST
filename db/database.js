'use strict';

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

// In production, set DB_PATH env var to a persistent volume path (e.g. /data/app.db)
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'app.db');

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT    UNIQUE NOT NULL COLLATE NOCASE,
      email       TEXT    UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT  NOT NULL,
      role        TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
      status      TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      last_login  TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id    INTEGER,
      actor_name  TEXT,
      action      TEXT NOT NULL,
      target_id   INTEGER,
      target_name TEXT,
      detail      TEXT,
      created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Migration: add 2FA columns if they don't already exist
  try { db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT'); } catch {}
  try { db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0'); } catch {}

  // Seed the initial admin account if no admin exists
  const adminExists = db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
  if (!adminExists) {
    const hash = bcrypt.hashSync('Admin@1234', 12);
    db.prepare(`
      INSERT INTO users (username, email, password_hash, role, status)
      VALUES ('admin', 'admin@localhost', ?, 'admin', 'active')
    `).run(hash);
    console.log('=======================================================');
    console.log('  Initial admin account created:');
    console.log('    Username : admin');
    console.log('    Password : Admin@1234');
    console.log('  IMPORTANT: Change this password after first login!');
    console.log('=======================================================');
  }
}

module.exports = { getDb };
