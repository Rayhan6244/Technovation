import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbFile = path.join(__dirname, 'traffic_bondhu.sqlite');
sqlite3.verbose();
const db = new sqlite3.Database(dbFile);

// Initialize tables
// Users: general users (drivers/citizens)
// Police: police officers
// Sessions handled by connect-sqlite3 separately

const init = () => {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      dob TEXT NOT NULL,
      nid TEXT NOT NULL UNIQUE,
      license TEXT NOT NULL UNIQUE,
      address TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS police_officers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      police_id TEXT NOT NULL UNIQUE,
      nid TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS violations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      officer_id INTEGER,
      type TEXT,
      amount INTEGER,
      status TEXT DEFAULT 'unpaid',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(officer_id) REFERENCES police_officers(id)
    )`);
  });
};

const get = (sql, params=[]) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});

const all = (sql, params=[]) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});

const run = (sql, params=[]) => new Promise((resolve, reject) => {
  db.run(sql, params, function(err){
    if (err) return reject(err);
    resolve({ id: this.lastID, changes: this.changes });
  });
});

export { db, init, get, all, run };
