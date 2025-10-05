import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import { init, get, run } from './db.js';
import { all } from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SQLiteStore = SQLiteStoreFactory(session);
const app = express();
let PORT = parseInt(process.env.PORT, 10) || 3000;
const SALT_ROUNDS = 10;

init();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Disable caching for API auth-related responses to avoid stale browser cache interference
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

const sessionCookieOptions = {
  maxAge: 1000 * 60 * 60 * 2, // 2 hours
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
};

app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: sessionCookieOptions
}));

// Utility to build a safe session user object
const buildSessionUser = (row, role) => ({ id: row.id, role, full_name: row.full_name });

// Helper to finalize login with session regeneration
function finalizeLogin(req, res, userPayload, message) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate failed', err);
      return fail(res, 'Session error', 500);
    }
    req.session.user = userPayload;
    req.session.save(saveErr => {
      if (saveErr) {
        console.error('Session save failed', saveErr);
        return fail(res, 'Session error', 500);
      }
      console.log('[LOGIN] session established', { sessionID: req.sessionID, role: userPayload.role, userId: userPayload.id });
      ok(res, { message, user: userPayload });
    });
  });
}

// Serve static files (public portal, top-level pages, police portal)
app.use(express.static(path.join(__dirname)));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/police', express.static(path.join(__dirname, 'police portal')));

// Serve landing page at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Landing.html'));
});

// Helper to standardize responses
const ok = (res, data) => res.json({ success: true, ...data });
const fail = (res, message, code=400) => res.status(code).json({ success: false, message });

// User signup
app.post('/api/signup/user', async (req, res) => {
  try {
    const { full_name, dob, nid, license, address, email, phone, password } = req.body;
    if (!full_name || !dob || !nid || !license || !address || !email || !phone || !password) {
      return fail(res, 'Missing fields');
    }
    const existing = await get(`SELECT id FROM users WHERE nid=? OR license=? OR email=? OR phone=?`, [nid, license, email, phone]);
    if (existing) return fail(res, 'User already exists');
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await run(`INSERT INTO users (full_name, dob, nid, license, address, email, phone, password_hash) VALUES (?,?,?,?,?,?,?,?)`, [full_name, dob, nid, license, address, email, phone, hash]);
    req.session.user = { id: result.id, role: 'user', full_name };
    ok(res, { message: 'User created', user: req.session.user });
  } catch (e) {
    console.error(e);
    fail(res, 'Signup failed');
  }
});

// Police signup
app.post('/api/signup/police', async (req, res) => {
  try {
    const { full_name, police_id, nid, email, phone, password } = req.body;
    if (!full_name || !police_id || !nid || !email || !phone || !password) {
      return fail(res, 'Missing fields');
    }
    const existing = await get(`SELECT id FROM police_officers WHERE police_id=? OR nid=? OR email=? OR phone=?`, [police_id, nid, email, phone]);
    if (existing) return fail(res, 'Officer already exists');
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await run(`INSERT INTO police_officers (full_name, police_id, nid, email, phone, password_hash) VALUES (?,?,?,?,?,?)`, [full_name, police_id, nid, email, phone, hash]);
    req.session.user = { id: result.id, role: 'police', full_name };
    ok(res, { message: 'Officer created', user: req.session.user });
  } catch (e) {
    console.error(e);
    fail(res, 'Signup failed');
  }
});

// Login (user)
app.post('/api/login/user', async (req, res) => {
  try {
    const { phone, license, password } = req.body;
    if (!phone || !license || !password) return fail(res, 'Missing fields');
    const row = await get(`SELECT * FROM users WHERE phone=? AND license=?`, [phone, license]);
    if (!row) return fail(res, 'User not found', 404);
    const okPass = await bcrypt.compare(password, row.password_hash);
    if (!okPass) return fail(res, 'Invalid credentials', 401);
    finalizeLogin(req, res, buildSessionUser(row, 'user'), 'Logged in');
  } catch (e) {
    console.error(e);
    fail(res, 'Login failed');
  }
});

// Login (police)
app.post('/api/login/police', async (req, res) => {
  try {
    const { police_id, password } = req.body;
    if (!police_id || !password) return fail(res, 'Missing fields');
    const row = await get(`SELECT * FROM police_officers WHERE police_id=?`, [police_id]);
    if (!row) return fail(res, 'Officer not found', 404);
    const okPass = await bcrypt.compare(password, row.password_hash);
    if (!okPass) return fail(res, 'Invalid credentials', 401);
    finalizeLogin(req, res, buildSessionUser(row, 'police'), 'Logged in');
  } catch (e) {
    console.error(e);
    fail(res, 'Login failed');
  }
});

app.post('/api/logout', (req, res) => {
  if (!req.session) return ok(res, { message: 'Logged out' });
  req.session.destroy(err => {
    if (err) {
      console.error('Session destroy failed', err);
      return fail(res, 'Logout error', 500);
    }
    res.clearCookie('connect.sid', { path: sessionCookieOptions.path, sameSite: sessionCookieOptions.sameSite });
    console.log('[LOGOUT] session destroyed');
    ok(res, { message: 'Logged out' });
  });
});

// Debug endpoint to inspect current session (do not enable in production without auth restriction)
app.get('/api/debug/session', (req, res) => {
  res.json({ sessionID: req.sessionID, user: req.session.user || null });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return fail(res, 'Not authenticated', 401);
  ok(res, { user: req.session.user });
});

// User stats (requires auth)
app.get('/api/user/stats', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'user') return fail(res, 'Not authenticated', 401);
    const userId = req.session.user.id;

    const totalViolationsRow = await get(`SELECT COUNT(*) as count FROM violations WHERE user_id=?`, [userId]);
    const pendingFinesRow = await get(`SELECT COALESCE(SUM(amount),0) as pending_total FROM violations WHERE user_id=? AND status='unpaid'`, [userId]);
    const paidFinesRow = await get(`SELECT COALESCE(SUM(amount),0) as paid_total FROM violations WHERE user_id=? AND status='paid'`, [userId]);

    // Clearance status rule: Valid if no unpaid violations
    const clearanceStatus = (pendingFinesRow.pending_total === 0) ? 'Valid' : 'Pending Dues';

    ok(res, {
      stats: {
        totalViolations: totalViolationsRow.count,
        pendingFines: pendingFinesRow.pending_total,
        paidFines: paidFinesRow.paid_total,
        clearanceStatus
      }
    });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not fetch stats');
  }
});

// User fines list (requires auth)
app.get('/api/user/fines', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'user') return fail(res, 'Not authenticated', 401);
    const userId = req.session.user.id;
    const rows = await all(`SELECT id, type, amount, status, created_at FROM violations WHERE user_id=? ORDER BY created_at DESC`, [userId]);
    ok(res, { fines: rows });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not fetch fines');
  }
});

// Pay a fine (user)
app.post('/api/user/fines/:id/pay', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'user') return fail(res, 'Not authenticated', 401);
    const userId = req.session.user.id;
    const { id } = req.params;
    const fine = await get(`SELECT id, user_id, status FROM violations WHERE id=?`, [id]);
    if (!fine || fine.user_id !== userId) return fail(res, 'Not found', 404);
    if (fine.status === 'paid') return ok(res, { message: 'Already paid' });
    await run(`UPDATE violations SET status='paid' WHERE id=?`, [id]);
    const updated = await get(`SELECT id, type, amount, status, created_at FROM violations WHERE id=?`, [id]);
    ok(res, { message: 'Fine paid', fine: updated });
  } catch (e) {
    console.error(e);
    fail(res, 'Payment failed');
  }
});

// ---------------- Police Data Sync Endpoints ----------------
const requireRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role) return fail(res, 'Not authenticated', 401);
  next();
};

// List all recent violations with driver info (police only)
app.get('/api/police/violations', requireRole('police'), async (req, res) => {
  try {
    const rows = await all(`SELECT v.id, v.type, v.amount, v.status, v.created_at, u.full_name AS driver_name, u.license AS license
                             FROM violations v
                             LEFT JOIN users u ON v.user_id = u.id
                             ORDER BY v.created_at DESC LIMIT 200`);
    ok(res, { violations: rows });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not fetch violations');
  }
});

// Create a new violation by driver license (police only)
app.post('/api/police/violations', requireRole('police'), async (req, res) => {
  try {
    const { license, type, amount } = req.body;
    if (!license || !type || amount == null) return fail(res, 'Missing fields');
    const userRow = await get(`SELECT id, full_name FROM users WHERE license=?`, [license]);
    if (!userRow) return fail(res, 'Driver not found', 404);
    const officerId = req.session.user.id;
    const result = await run(`INSERT INTO violations (user_id, officer_id, type, amount, status) VALUES (?,?,?,?, 'unpaid')`, [userRow.id, officerId, type, amount]);
    const created = await get(`SELECT id, type, amount, status, created_at FROM violations WHERE id=?`, [result.id]);
    ok(res, { message: 'Violation created', violation: { ...created, driver_name: userRow.full_name, license } });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not create violation');
  }
});

// Update violation status (police only)
app.patch('/api/police/violations/:id', requireRole('police'), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // expected: unpaid | paid | disputed
    if (!['unpaid', 'paid', 'disputed'].includes(status)) return fail(res, 'Invalid status');
    const existing = await get(`SELECT id FROM violations WHERE id=?`, [id]);
    if (!existing) return fail(res, 'Not found', 404);
    await run(`UPDATE violations SET status=? WHERE id=?`, [status, id]);
    const updated = await get(`SELECT id, type, amount, status, created_at FROM violations WHERE id=?`, [id]);
    ok(res, { message: 'Updated', violation: updated });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not update violation');
  }
});

// Police dashboard stats
app.get('/api/police/stats', requireRole('police'), async (req, res) => {
  try {
    // Daily (based on local date)
    const dailyViolations = await get(`SELECT COUNT(*) as count FROM violations WHERE DATE(created_at)=DATE('now','localtime')`);
    const dailyRevenue = await get(`SELECT COALESCE(SUM(amount),0) as total FROM violations WHERE status='paid' AND DATE(created_at)=DATE('now','localtime')`);
    const pendingFines = await get(`SELECT COUNT(*) as count FROM violations WHERE status='unpaid'`);
    // Placeholder for high alerts (no table yet) -> derive from high unpaid amount or arbitrary rule
    const highAlerts = await get(`SELECT COUNT(*) as count FROM violations WHERE status='unpaid' AND amount >= 1000`);
    // Recent fines list
    const recent = await all(`SELECT v.id, v.type, v.amount, v.status, u.full_name AS driver_name
                              FROM violations v LEFT JOIN users u ON v.user_id = u.id
                              ORDER BY v.created_at DESC LIMIT 10`);
    ok(res, {
      stats: {
        dailyViolations: dailyViolations.count,
        pendingFines: pendingFines.count,
        dailyRevenue: dailyRevenue.total,
        highAlerts: highAlerts.count
      },
      recent: recent.map(r => ({
        id: r.id,
        driver_name: r.driver_name,
        type: r.type,
        amount: r.amount,
        status: r.status
      }))
    });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not fetch stats');
  }
});

// Catch-all 404 for API
app.use('/api', (req, res) => fail(res, 'Not found', 404));

const startServer = (attempts=0) => {
  const server = app.listen(PORT, () => {
    console.log(`Server running: http://localhost:${PORT}`);
  });
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE' && attempts < 5) {
      console.warn(`Port ${PORT} in use, trying ${PORT+1}...`);
      PORT += 1;
      setTimeout(()=>startServer(attempts+1), 300);
    } else {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  });
};

startServer();
