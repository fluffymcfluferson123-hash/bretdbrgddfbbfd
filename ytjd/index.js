// index.js — ESM server: Users CRUD, Analytics, Bans, Warnings, Notifications, Owner OP, Roadmaps
import 'dotenv/config';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { createBareServer } from '@tomphttp/bare-server-node';
import cors from 'cors';
import express from 'express';
import basicAuth from 'express-basic-auth';
import cookieParser from 'cookie-parser';
import mime from 'mime';
import fetch from 'node-fetch';
import config from './config.js';
import { setupMasqr } from './Masqr.js';
import bcrypt from 'bcryptjs';
import pg from 'pg';

const { Pool } = pg;

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL not set'); process.exit(1); }
if (!process.env.SESSION_SECRET) { console.error('SESSION_SECRET not set'); process.exit(1); }

let pool;
try {
  pool = new Pool({ connectionString: process.env.DATABASE_URL });

  // ---- Core tables ----
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      device_id TEXT UNIQUE,
      recovery_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS device_id TEXT UNIQUE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      audience TEXT NOT NULL CHECK (audience IN ('global','user')),
      to_username TEXT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notification_reads (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
      read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, notification_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notification_dismissals (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
      dismissed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, notification_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      bg_url TEXT,
      theme TEXT,
      particles_enabled BOOLEAN DEFAULT FALSE,
      data JSONB DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // ---- Bans ----
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_bans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scopes TEXT[] NOT NULL DEFAULT ARRAY['site'],
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ
    )
  `);

  // ---- Warnings ----
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_warnings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info', -- info|low|med|high
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_by TEXT NOT NULL DEFAULT 'Owner',
      revoked_at TIMESTAMPTZ
    )
  `);

  // ---- Analytics events (anonymized IP) ----
  await pool.query(`
    CREATE TABLE IF NOT EXISTS site_events (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      username TEXT,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      status INTEGER NOT NULL,
      ms INTEGER NOT NULL,
      ip_hash TEXT,
      ua TEXT
    )
  `);

  // ---- Roadmaps (owner managed; public readable if visible) ----
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'roadmap_visibility') THEN
        CREATE TYPE roadmap_visibility AS ENUM ('public', 'private');
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'roadmap_status') THEN
        CREATE TYPE roadmap_status AS ENUM ('draft','active','archived');
      END IF;
    END$$;
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS roadmaps (
      id SERIAL PRIMARY KEY,
      slug TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      visibility roadmap_visibility NOT NULL DEFAULT 'public',
      status roadmap_status NOT NULL DEFAULT 'active',
      sort INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_sort ON roadmaps(sort, updated_at DESC)`);

  // ---- indexes ----
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications (created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_audience_user ON notifications (audience, to_username)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notification_reads_user ON notification_reads (user_id, notification_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notification_dismissals_user ON notification_dismissals (user_id, notification_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_bans_user ON user_bans (user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_events_ts ON site_events (ts DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_events_path ON site_events (path)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_events_username ON site_events (username)`);

  const ownerCheck = await pool.query('SELECT 1 FROM users WHERE username=$1', ['Owner']);
  if (!ownerCheck.rows.length) {
    const hash = await bcrypt.hash('root', 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1,$2)', ['Owner', hash]);
    console.log('Seeded owner account (username: Owner, password: root)');
  }
  console.log('[db] ready');
} catch (err) {
  console.error('Failed to initialize database', err);
  process.exit(1);
}

const COOKIE_NAME = 'sid';
function sign(val){ return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(val).digest('hex'); }
function setSession(res, username){
  const v = Buffer.from(username).toString('base64');
  res.cookie(COOKIE_NAME, `${v}.${sign(v)}`, { httpOnly:true, sameSite:'lax', secure:false, path:'/', maxAge:30*24*3600*1000 });
}
function clearSession(res){
  res.cookie(COOKIE_NAME, '', { httpOnly:true, sameSite:'lax', secure:false, path:'/', maxAge:0 });
}
function readSession(req){
  const raw = req.cookies[COOKIE_NAME];
  if (!raw) return null;
  const [v, sig] = raw.split('.');
  if (!v || !sig) return null;
  if (sign(v) !== sig) return null;
  try { return Buffer.from(v, 'base64').toString(); } catch { return null; }
}

const __dirname = process.cwd();
const server = http.createServer();
const app = express();
const bareServer = createBareServer('/ov/');
const PORT = process.env.PORT || 8080;

if (process.env.config === 'true' && config?.challenge) {
  console.log(`Password protection is enabled. Users: ${Object.keys(config.users)}`);
  app.use(basicAuth({ users: config.users, challenge: true }));
}

// ---- Ensure fresh session-nav.js
app.use((req, res, next) => {
  if (req.path === '/static/session-nav.js') {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
  }
  next();
});

// ---- Asset proxy cache
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000;
app.get('/e/*', async (req, res, next) => {
  if (cache.has(req.path)) {
    const { data, contentType, timestamp } = cache.get(req.path);
    if (Date.now() - timestamp <= CACHE_TTL) {
      res.writeHead(200, { 'Content-Type': contentType });
      return res.end(data);
    }
    cache.delete(req.path);
  }
  try {
    const baseUrls = {
      '/e/1/': 'https://raw.githubusercontent.com/v-5x/x/fixy/',
      '/e/2/': 'https://raw.githubusercontent.com/ypxa/y/main/',
      '/e/3/': 'https://raw.githubusercontent.com/ypxa/w/master/',
    };
    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }
    if (!reqTarget) return next();
    const asset = await fetch(reqTarget);
    if (asset.status !== 200) return next();
    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = ['.unityweb'];
    const contentType = no.includes(ext) ? 'application/octet-stream' : (mime.getType(ext) || 'application/octet-stream');
    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  } catch (error) {
    console.error(error);
    res.setHeader('Content-Type', 'text/html');
    res.status(500).send('Error fetching the asset');
  }
});

// ---- Middleware
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
if (process.env.MASQR === 'true') setupMasqr(app);

// ---- Analytics logger (anonymized ip)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', async () => {
    try {
      const username = readSession(req) || null;
      const ms = Date.now() - start;
      const status = res.statusCode;
      const method = req.method;
      const pathOnly = req.path;
      const ua = (req.headers['user-agent'] || '').slice(0, 200);
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const ip_hash = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(ip).digest('hex').slice(0, 32);
      await pool.query(
        'INSERT INTO site_events (username, path, method, status, ms, ip_hash, ua) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [username, pathOnly, method, status, ms, ip_hash, ua]
      );
    } catch { /* ignore */ }
  });
  next();
});

app.use(express.static(path.join(__dirname, 'static')));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/ov', cors({ origin: true }));

// ---- Health
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ---- Helpers
function isOwner(req) { return readSession(req) === 'Owner'; }

async function getUserRowByUsername(username) {
  const r = await pool.query('SELECT id, username FROM users WHERE username=$1', [username]);
  return r.rows[0] || null;
}

async function getActiveScopesByUserId(userId) {
  const r = await pool.query(
    `SELECT scopes FROM user_bans
     WHERE user_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`,
    [userId]
  );
  const scopes = new Set();
  for (const row of r.rows) for (const s of (row.scopes || [])) scopes.add(s);
  return scopes;
}

const BAN_WHITELIST_PREFIX = ['/static', '/assets', '/ov', '/e/', '/healthz', '/favicon', '/robots', '/manifest'];
const BAN_WHITELIST_EXACT = new Set([
  '/', '/li', '/si', '/signup', '/forgot',
  '/api/login', '/api/signup', '/api/forgot/reset', '/api/session', '/api/logout', '/api/notifications'
]);

function wantsHTML(req){
  const a = (req.headers.accept || '').toLowerCase();
  return a.includes('text/html') || a.includes('*/*') || a === '';
}
const startsWithAny = (p, arr) => arr.some(x => p.startsWith(x));

// ---- Site-wide ban enforcement
app.use(async (req, res, next) => {
  const username = readSession(req);
  if (!username || username === 'Owner') return next();
  const p = req.path;
  if (BAN_WHITELIST_EXACT.has(p) || startsWithAny(p, BAN_WHITELIST_PREFIX)) return next();
  try {
    const u = await getUserRowByUsername(username);
    if (!u) return next();
    const scopes = await getActiveScopesByUserId(u.id);
    if (scopes.has('site')) {
      if (wantsHTML(req)) return res.status(403).sendFile(path.join(__dirname, 'static', 'banned.html'));
      return res.status(403).json({ error:'Banned' });
    }
    return next();
  } catch { return next(); }
});

// ---- Auth
app.post('/api/signup', async (req, res) => {
  const { username, password, deviceId } = req.body || {};
  if (!username || !password || password.length < 8 || !deviceId) return res.status(400).json({ error:'Invalid input' });
  try {
    const device = await pool.query('SELECT 1 FROM users WHERE device_id=$1', [deviceId]);
    if (device.rows.length) return res.status(429).json({ error:'This device already has an account' });
    const hash = await bcrypt.hash(password, 10);
    const recovery_code = crypto.randomBytes(12).toString('hex');
    await pool.query('INSERT INTO users (username, password, device_id, recovery_code) VALUES ($1,$2,$3,$4)', [username, hash, deviceId, recovery_code]);
    setSession(res, username);
    res.json({ success:true, recovery_code });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error:'Username already exists' });
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Missing fields' });
  try {
    const { rows } = await pool.query('SELECT password FROM users WHERE username=$1', [username]);
    if (rows.length && (await bcrypt.compare(password, rows[0].password))) {
      setSession(res, username);
      res.json({ success:true });
    } else {
      res.status(401).json({ error:'Invalid credentials' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/logout', (req, res) => { clearSession(res); res.json({ success:true }); });

app.post('/api/forgot/reset', async (req, res) => {
  const { username, recovery_code, new_password } = req.body || {};
  if (!username || !recovery_code || !new_password || new_password.length < 8) return res.status(400).json({ error:'Invalid input' });
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE username=$1 AND recovery_code=$2', [username, recovery_code]);
    if (!rows.length) return res.status(404).json({ error:'Not found' });
    const hash = await bcrypt.hash(new_password, 10);
    const newCode = crypto.randomBytes(12).toString('hex');
    await pool.query('UPDATE users SET password=$1, recovery_code=$2 WHERE id=$3', [hash, newCode, rows[0].id]);
    res.json({ success:true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.get('/api/session', (req, res) => {
  const username = readSession(req);
  if (username) res.json({ authenticated:true, username, role: username === 'Owner' ? 'owner' : 'user' });
  else res.json({ authenticated:false });
});

// ---- Notifications (locked for guests by returning empty) ----
const BODY_LONG_THRESHOLD = 160;

app.get('/api/notifications', async (req, res) => {
  const username = readSession(req);
  if (!username) return res.json({ items:[], unread:0 }); // lock for guests
  try {
    const userRow = await pool.query('SELECT id, created_at FROM users WHERE username=$1', [username]);
    if (!userRow.rows.length) return res.json({ items:[], unread:0 });
    const userId = userRow.rows[0].id;
    const signedUpAt = userRow.rows[0].created_at;

    const { rows } = await pool.query(
      `SELECT n.id, n.title, n.body, n.created_at,
              (nr.notification_id IS NOT NULL) AS read,
              (char_length(n.body) > $4) AS is_long,
              CASE WHEN char_length(n.body) > $4 THEN substr(n.body, 1, $4) ELSE n.body END AS preview
       FROM notifications n
       LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.user_id = $1
       LEFT JOIN notification_dismissals nd ON nd.notification_id = n.id AND nd.user_id = $1
       WHERE nd.notification_id IS NULL
         AND n.created_at >= $2
         AND (n.audience='global' OR (n.audience='user' AND n.to_username=$3))
       ORDER BY n.created_at DESC
       LIMIT 100`,
      [userId, signedUpAt, username, BODY_LONG_THRESHOLD]
    );
    const unread = rows.filter(r => !r.read).length;
    res.json({ items:rows, unread, long_threshold: BODY_LONG_THRESHOLD });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/notifications/read', async (req, res) => {
  const username = readSession(req);
  if (!username) return res.status(401).json({ error:'Unauthorized' });
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error:'Missing id' });
  try {
    const u = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (!u.rows.length) return res.status(400).json({ error:'Invalid user' });
    await pool.query('INSERT INTO notification_reads (user_id, notification_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [u.rows[0].id, id]);
    res.json({ success:true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/notifications/mark-all-read', async (req, res) => {
  const username = readSession(req);
  if (!username) return res.status(401).json({ error:'Unauthorized' });
  try {
    const u = await pool.query('SELECT id, created_at FROM users WHERE username=$1', [username]);
    if (!u.rows.length) return res.status(400).json({ error:'Invalid user' });
    const userId = u.rows[0].id;
    const signedUpAt = u.rows[0].created_at;
    await pool.query(
      `INSERT INTO notification_reads (user_id, notification_id)
       SELECT $1, n.id
       FROM notifications n
       WHERE n.created_at >= $2
         AND (n.audience='global' OR (n.audience='user' AND n.to_username=$3))
       ON CONFLICT DO NOTHING`,
      [userId, signedUpAt, username]
    );
    res.json({ success:true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/notifications/delete', async (req, res) => {
  const username = readSession(req);
  if (!username) return res.status(401).json({ error:'Unauthorized' });
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error:'Missing id' });
  try {
    const u = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (!u.rows.length) return res.status(400).json({ error:'Invalid user' });
    const n = await pool.query('SELECT 1 FROM notifications WHERE id=$1', [id]);
    if (!n.rows.length) return res.status(404).json({ error:'Notification not found' });
    await pool.query('INSERT INTO notification_dismissals (user_id, notification_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [u.rows[0].id, id]);
    await pool.query('INSERT INTO notification_reads (user_id, notification_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [u.rows[0].id, id]);
    res.json({ success:true });
  } catch (err) {
    console.error('delete error', err);
    res.status(500).json({ error:'Server error' });
  }
});

// ---- Roadmaps (public read; owner manage)
app.get('/api/roadmaps', async (req, res) => {
  const is_owner = isOwner(req);
  try {
    const rows = (await pool.query(
      is_owner
        ? `SELECT id, slug, title, left(body, 280) AS excerpt, visibility, status, sort, updated_at
           FROM roadmaps
           ORDER BY sort ASC, updated_at DESC`
        : `SELECT id, slug, title, left(body, 280) AS excerpt, visibility, status, sort, updated_at
           FROM roadmaps
           WHERE visibility='public' AND status IN ('active')
           ORDER BY sort ASC, updated_at DESC`
    )).rows;
    res.json({ items: rows });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/roadmaps/:slug', async (req, res) => {
  const is_owner = isOwner(req);
  const { slug } = req.params;
  try {
    const r = (await pool.query(
      `SELECT id, slug, title, body, visibility, status, sort, updated_at
         FROM roadmaps WHERE slug=$1`, [slug]
    )).rows[0];
    if (!r) return res.status(404).json({ error:'Not found' });
    if (!is_owner && (r.visibility !== 'public' || r.status === 'archived')) {
      return res.status(403).json({ error:'Forbidden' });
    }
    res.json({ item: r });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// ---- Roadmaps admin (Owner only)
app.post('/api/admin/roadmaps/create', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { slug, title, body, visibility='public', status='active', sort=0 } = req.body || {};
  if (!slug || !title || !body) return res.status(400).json({ error:'slug, title, body required' });
  try {
    const r = await pool.query(
      `INSERT INTO roadmaps (slug, title, body, visibility, status, sort)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, slug, title, visibility, status, sort, updated_at`,
      [slug, title, body, visibility, status, Number(sort)||0]
    );
    res.json({ success:true, item: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error:'slug already exists' });
    console.error(e); res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/admin/roadmaps/update', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { id, slug, title, body, visibility, status, sort } = req.body || {};
  if (!id && !slug) return res.status(400).json({ error:'id or slug required' });
  try {
    const by = id ? 'id' : 'slug';
    const val = id ?? slug;
    const r = await pool.query(
      `UPDATE roadmaps SET
         slug = COALESCE($2, slug),
         title = COALESCE($3, title),
         body = COALESCE($4, body),
         visibility = COALESCE($5, visibility),
         status = COALESCE($6, status),
         sort = COALESCE($7, sort),
         updated_at = NOW()
       WHERE ${by}=$1
       RETURNING id, slug, title, visibility, status, sort, updated_at`,
      [val, slug || null, title || null, body || null, visibility || null, status || null, (sort ?? null)]
    );
    if (!r.rows.length) return res.status(404).json({ error:'Not found' });
    res.json({ success:true, item: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error:'slug already exists' });
    console.error(e); res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/admin/roadmaps/delete', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { id, slug } = req.body || {};
  if (!id && !slug) return res.status(400).json({ error:'id or slug required' });
  try {
    const by = id ? 'id' : 'slug';
    const val = id ?? slug;
    const r = await pool.query(`DELETE FROM roadmaps WHERE ${by}=$1 RETURNING id`, [val]);
    if (!r.rows.length) return res.status(404).json({ error:'Not found' });
    res.json({ success:true });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// ---- Owner Panel PAGE (before 404)
app.get(['/op', '/op/'], (req, res) => {
  if (!isOwner(req)) return res.redirect('/li');
  return res.sendFile(path.join(__dirname, 'static', 'op.html'));
});

// ---- Admin: Notifications (unchanged)
app.post('/api/admin/notify', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { audience, username: toUser, title, body } = req.body || {};
  if (!audience || !title || !body || (audience === 'user' && !toUser)) {
    return res.status(400).json({ error:'Invalid input' });
  }
  try {
    const { rows } = await pool.query(
      'INSERT INTO notifications (audience, to_username, title, body) VALUES ($1,$2,$3,$4) RETURNING id',
      [audience, audience === 'user' ? toUser : null, title, body]
    );
    res.json({ success:true, id: rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.get('/api/admin/notifications', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  try {
    const { rows } = await pool.query(
      'SELECT id, audience, to_username, title, body, created_at FROM notifications ORDER BY created_at DESC LIMIT 50'
    );
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

// ---- Admin: Bans / Warnings / Users / Analytics (same as your last good version)
function addRelative(date, amount, unit){
  const d = new Date(date.getTime());
  const n = Number(amount||0);
  switch (unit) {
    case 'minutes': d.setMinutes(d.getMinutes()+n); break;
    case 'hours': d.setHours(d.getHours()+n); break;
    case 'days': d.setDate(d.getDate()+n); break;
    case 'weeks': d.setDate(d.getDate()+7*n); break;
    case 'months': d.setMonth(d.getMonth()+n); break;
    default: d.setDate(d.getDate()+n); break;
  }
  return d;
}

app.post('/api/admin/ban', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { username, reason, scopes, mode, amount, unit, expires_at } = req.body || {};
  if (!username || !Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({ error:'username and scopes required' });
  }
  if (username === 'Owner') return res.status(400).json({ error:'Cannot ban Owner' });
  try {
    const u = await getUserRowByUsername(username);
    if (!u) return res.status(404).json({ error:'User not found' });
    let expires = null;
    if (mode === 'relative') {
      const amt = Number(amount||0);
      if (!(amt > 0) || !unit) return res.status(400).json({ error:'Invalid duration' });
      expires = addRelative(new Date(), amt, unit);
    } else if (mode === 'absolute') {
      if (!expires_at) return res.status(400).json({ error:'expires_at required' });
      const d = new Date(expires_at);
      if (isNaN(d.getTime())) return res.status(400).json({ error:'Invalid expires_at' });
      expires = d;
    }
    const { rows } = await pool.query(
      `INSERT INTO user_bans (user_id, scopes, reason, expires_at)
       VALUES ($1,$2,$3,$4)
       RETURNING id, user_id, scopes, reason, created_at, expires_at`,
      [u.id, scopes.includes('site') ? ['site'] : scopes, reason || null, expires]
    );
    res.json({ success:true, ban: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/admin/unban', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { username, ban_id } = req.body || {};
  try {
    if (ban_id) {
      await pool.query(`UPDATE user_bans SET expires_at = NOW() WHERE id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, [ban_id]);
      return res.json({ success:true });
    }
    if (!username) return res.status(400).json({ error:'username or ban_id required' });
    const u = await getUserRowByUsername(username);
    if (!u) return res.status(404).json({ error:'User not found' });
    await pool.query(`UPDATE user_bans SET expires_at = NOW() WHERE user_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, [u.id]);
    res.json({ success:true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.get('/api/admin/bans', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const showAll = String(req.query.all || '0') === '1';
  try {
    const q = showAll
      ? `SELECT b.id, u.username, b.scopes, b.reason, b.created_at, b.expires_at
           FROM user_bans b JOIN users u ON u.id=b.user_id
          ORDER BY (b.expires_at IS NULL) DESC, b.expires_at DESC NULLS LAST, b.created_at DESC
          LIMIT 200`
      : `SELECT b.id, u.username, b.scopes, b.reason, b.created_at, b.expires_at
           FROM user_bans b JOIN users u ON u.id=b.user_id
          WHERE (b.expires_at IS NULL OR b.expires_at > NOW())
          ORDER BY (b.expires_at IS NULL) DESC, b.expires_at ASC NULLS LAST, b.created_at DESC
          LIMIT 200`;
    const { rows } = await pool.query(q);
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/admin/warn', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const { username, reason, severity } = req.body || {};
  if (!username || !reason) return res.status(400).json({ error:'username and reason required' });
  try {
    const u = await getUserRowByUsername(username);
    if (!u) return res.status(404).json({ error:'User not found' });

    const sev = ['info','low','med','high'].includes(severity) ? severity : 'info';

    const { rows } = await pool.query(
      `INSERT INTO user_warnings (user_id, reason, severity, created_by)
       VALUES ($1,$2,$3,$4)
       RETURNING id, user_id, reason, severity, created_at, created_by`,
      [u.id, reason, sev, 'Owner']
    );

    await pool.query(
      'INSERT INTO notifications (audience, to_username, title, body) VALUES ($1,$2,$3,$4)',
      ['user', username, `⚠️ Warning (${sev})`, reason]
    );

    res.json({ success:true, warning: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.get('/api/admin/warnings', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const filterUser = (req.query.username || '').trim();
  try {
    let rows;
    if (filterUser) {
      rows = (await pool.query(
        `SELECT w.id, u.username, w.reason, w.severity, w.created_at, w.created_by, w.revoked_at
           FROM user_warnings w
           JOIN users u ON u.id = w.user_id
          WHERE u.username=$1
          ORDER BY w.created_at DESC
          LIMIT 200`,
        [filterUser]
      )).rows;
    } else {
      rows = (await pool.query(
        `SELECT w.id, u.username, w.reason, w.severity, w.created_at, w.created_by, w.revoked_at
           FROM user_warnings w
           JOIN users u ON u.id = w.user_id
          ORDER BY w.created_at DESC
          LIMIT 200`
      )).rows;
    }
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error:'Server error' });
  }
});

app.get('/api/admin/analytics/summary', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const days = Math.min(90, Math.max(1, parseInt(req.query.days || '7', 10)));
  try {
    const since = `${days} days`;
    const pv = (await pool.query(`SELECT COUNT(*)::bigint c FROM site_events WHERE ts >= NOW() - INTERVAL '${since}'`)).rows[0].c;
    const uv = (await pool.query(`SELECT COUNT(DISTINCT ip_hash)::bigint c FROM site_events WHERE ts >= NOW() - INTERVAL '${since}'`)).rows[0].c;
    const au = (await pool.query(`SELECT COUNT(DISTINCT username)::bigint c FROM site_events WHERE ts >= NOW() - INTERVAL '${since}' AND username IS NOT NULL`)).rows[0].c;
    res.json({ pageviews: Number(pv), uniques: Number(uv), active_users: Number(au), days });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/admin/analytics/timeseries', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const days = Math.min(90, Math.max(1, parseInt(req.query.days || '7', 10)));
  const bucket = (req.query.bucket || 'day').toLowerCase(); // 'hour' | 'day'
  const trunc = bucket === 'hour' ? 'hour' : 'day';
  try {
    const rows = (await pool.query(
      `SELECT date_trunc('${trunc}', ts) AS bucket, COUNT(*)::bigint pv
         FROM site_events
        WHERE ts >= NOW() - INTERVAL '${days} days'
        GROUP BY 1 ORDER BY 1`
    )).rows;
    res.json({ items: rows });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/admin/analytics/top-paths', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const days = Math.min(90, Math.max(1, parseInt(req.query.days || '7', 10)));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  try {
    const rows = (await pool.query(
      `SELECT path, COUNT(*)::bigint pv
         FROM site_events
        WHERE ts >= NOW() - INTERVAL '${days} days'
        GROUP BY path ORDER BY pv DESC LIMIT $1`, [limit]
    )).rows;
    res.json({ items: rows });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/admin/analytics/top-users', async (req, res) => {
  if (!isOwner(req)) return res.status(403).json({ error:'Forbidden' });
  const days = Math.min(90, Math.max(1, parseInt(req.query.days || '7', 10)));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  try {
    const rows = (await pool.query(
      `SELECT username, COUNT(*)::bigint pv
         FROM site_events
        WHERE ts >= NOW() - INTERVAL '${days} days' AND username IS NOT NULL
        GROUP BY username ORDER BY pv DESC LIMIT $1`, [limit]
    )).rows;
    res.json({ items: rows });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// ---- Per-route scope guard helper
async function ensureAccess(req, res, routeKey) {
  const username = readSession(req);
  if (!username || username === 'Owner') return true;
  const u = await getUserRowByUsername(username);
  if (!u) return true;
  const scopes = await getActiveScopesByUserId(u.id);
  if (scopes.has('site') || scopes.has(routeKey)) {
    res.status(403).sendFile(path.join(__dirname, 'static', 'banned.html'));
    return false;
  }
  return true;
}

// ---- Static routes
const routes = [
  { path: '/as', file: 'apps.html',     auth: true,  scope: '/as' },
  { path: '/gm', file: 'games.html',    auth: true,  scope: '/gm' },
  { path: '/st', file: 'settings.html', auth: true,  scope: '/st' },
  { path: '/ta', file: 'tabs.html',     auth: false, scope: '/ta' },
  { path: '/ah', file: 'about.html',    auth: false, scope: null  },
  { path: '/li', file: 'login.html',    auth: false, scope: null  },
  { path: '/si', file: 'signup.html',   auth: false, scope: null  },
  { path: '/signup', file: 'signup.html', auth: false, scope: null },
  { path: '/forgot', file: 'forgot.html', auth: false, scope: null },
  { path: '/',   file: 'index.html',    auth: false, scope: null  },
  { path: '/tos', file: 'tos.html',     auth: false, scope: null  },
];

routes.forEach(({ path: routePath, file, auth, scope }) => {
  app.get(routePath, async (req, res) => {
    if (auth && !readSession(req)) return res.sendFile(path.join(__dirname, 'static', 'lock.html'));
    if (scope) { const ok = await ensureAccess(req, res, scope); if (!ok) return; }
    res.sendFile(path.join(__dirname, 'static', file));
  });
});

// ---- 404 LAST
app.use((req, res) => { res.status(404).sendFile(path.join(__dirname, 'static', '404.html')); });
app.use((err, req, res, next) => { console.error(err.stack); res.status(500).sendFile(path.join(__dirname, 'static', '404.html')); });

// ---- HTTP + bare
server.on('request', (req, res) => { if (bareServer.shouldRoute(req)) bareServer.routeRequest(req, res); else app(req, res); });
server.on('upgrade', (req, socket, head) => { if (bareServer.shouldRoute(req)) bareServer.routeUpgrade(req, socket, head); else socket.end(); });
server.on('listening', () => { console.log(`Running at http://localhost:${PORT}`); });
server.listen({ port: PORT, host: '0.0.0.0' });
