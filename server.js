'use strict';
// QR Attendance: zero-dependency Node server (needs Node 22.13+ for node:sqlite).
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const PROXY = process.env.TRUST_PROXY === '1';      // set to 1 when behind a host's HTTPS proxy
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'attendance.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','staff')), created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS students(code TEXT PRIMARY KEY, name TEXT NOT NULL, grp TEXT NOT NULL DEFAULT '', time_in INTEGER, time_out INTEGER, last_scan INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, who TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');`);
const q = sql => db.prepare(sql);

// ---------- helpers ----------
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = pw => { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex'); };
const checkPw = (pw, stored) => { const [s, h] = stored.split(':'); const a = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64), b = Buffer.from(h, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const norm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
const txt = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const AL = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const genCode = () => { let c; do { c = Array.from({ length: 10 }, () => AL[crypto.randomInt(AL.length)]).join(''); } while (q('SELECT 1 FROM students WHERE code=?').get(c)); return c; };
const audit = (who, action, detail = '') => q('INSERT INTO audit(at,who,action,detail) VALUES(?,?,?,?)').run(Date.now(), who, action, detail);

if (!q('SELECT 1 FROM users').get()) {
  const u = process.env.ADMIN_USER || 'admin'; let p = process.env.ADMIN_PASSWORD; const gen = !p;
  if (gen) p = crypto.randomBytes(9).toString('base64url');
  q('INSERT INTO users(username,pass,role,created) VALUES(?,?,?,?)').run(u, hashPw(p), 'admin', Date.now());
  console.log(gen ? `First run: created admin "${u}" with password ${p}  (change it after signing in)` : `First run: created admin "${u}" from environment variables`);
}

// ---------- rate limiting (in memory) ----------
const hits = new Map();
const recent = (k, win) => { const n = Date.now(), a = (hits.get(k) || []).filter(t => n - t < win); hits.set(k, a); return a; };
const note = k => { const a = hits.get(k) || []; a.push(Date.now()); hits.set(k, a); };
setInterval(() => { const n = Date.now(); for (const [k, a] of hits) if (!a.length || n - a[a.length - 1] > 3600e3) hits.delete(k); q('DELETE FROM sessions WHERE expires<?').run(n); }, 600e3).unref();
const ipOf = req => { if (PROXY) { const f = (req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean); if (f.length) return f[f.length - 1]; } return req.socket.remoteAddress || 'x'; };

// ---------- http plumbing ----------
const SEC = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; media-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(self), microphone=(), geolocation=()', ...(PROD ? { 'Strict-Transport-Security': 'max-age=31536000' } : {})
};
const send = (res, code, obj, extra = {}) => { res.writeHead(code, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra }); res.end(JSON.stringify(obj)); };
const page = (res, file) => { try { res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(fs.readFileSync(path.join(__dirname, 'public', file))); } catch (e) { send(res, 500, { error: 'Server error' }); } };
const readBody = req => new Promise((ok, no) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 2e6) { no(Object.assign(new Error('Request too large'), { status: 413 })); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch (e) { no(Object.assign(new Error('Invalid JSON'), { status: 400 })); } }); req.on('error', no); });
const cookie = (v, age) => `sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${PROD ? '; Secure' : ''}`;
const auth = req => { const m = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie || ''); if (!m) return null; const r = q('SELECT u.id,u.username,u.role,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(sha(m[1])); return r && r.expires > Date.now() ? r : null; };
const stats = () => q(`SELECT COUNT(*) AS total, COALESCE(SUM(time_in IS NOT NULL AND time_out IS NULL),0) AS inside, COALESCE(SUM(time_out IS NOT NULL),0) AS out FROM students`).get();
const fail = (status, error) => { throw Object.assign(new Error(error), { status }); };

async function api(req, res, route) {
  const GETS = ['me', 'stats', 'students', 'users'];
  if ((req.method === 'GET') !== GETS.includes(route)) fail(405, 'Method not allowed');
  const me = auth(req), ip = ipOf(req);
  const need = role => { if (!me) fail(401, 'Please sign in'); if (role && me.role !== role) fail(403, 'Admins only'); };
  const b = req.method === 'POST' ? await readBody(req) : {};

  if (route === 'lookup') {                         // public: parents (status only, no names)
    if (recent('p:' + ip, 60e3).length >= 30 || recent('pf:' + ip, 600e3).length >= 15) fail(429, 'Too many attempts. Please wait a few minutes.');
    note('p:' + ip);
    const s = q('SELECT time_in,time_out FROM students WHERE code=?').get(norm(b.code));
    if (!s) { note('pf:' + ip); return send(res, 200, { found: false }); }
    return send(res, 200, { found: true, time_in: s.time_in, time_out: s.time_out });
  }
  if (route === 'login') {
    const user = txt(b.username, 40).toLowerCase();
    if (recent('l:' + ip, 15 * 60e3).length >= 10 || recent('u:' + user, 15 * 60e3).length >= 20) fail(429, 'Too many sign-in attempts. Try again in 15 minutes.');
    const u = q('SELECT * FROM users WHERE username=?').get(user);
    const ok = u ? checkPw(String(b.password || ''), u.pass) : (checkPw('x', hashPw('y')), false);   // equalise timing
    if (!ok) { note('l:' + ip); note('u:' + user); audit(user || '?', 'login failed', ip); fail(401, 'Wrong username or password'); }
    const tok = crypto.randomBytes(32).toString('base64url');
    q('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(tok), u.id, Date.now() + 12 * 3600e3);
    audit(u.username, 'login');
    return send(res, 200, { username: u.username, role: u.role }, { 'Set-Cookie': cookie(tok, 43200) });
  }
  if (route === 'logout') { const m = /sid=([\w-]+)/.exec(req.headers.cookie || ''); if (m) q('DELETE FROM sessions WHERE token=?').run(sha(m[1])); return send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) }); }
  if (route === 'me') { need(); return send(res, 200, { username: me.username, role: me.role }); }
  if (route === 'stats') { need(); return send(res, 200, stats()); }

  if (route === 'scan') {                           // staff and admin
    need();
    const code = norm(b.code), s = q('SELECT * FROM students WHERE code=?').get(code), now = Date.now();
    if (!s) { audit(me.username, 'scan unknown', code); fail(404, 'Unknown code'); }
    let result;
    if (now - s.last_scan < 8000) result = 'dup';
    else if (!s.time_in) { q('UPDATE students SET time_in=?,last_scan=? WHERE code=?').run(now, now, code); s.time_in = now; result = 'in'; }
    else if (!s.time_out) { q('UPDATE students SET time_out=?,last_scan=? WHERE code=?').run(now, now, code); s.time_out = now; result = 'out'; }
    else result = 'done';
    if (result === 'in' || result === 'out') audit(me.username, 'time ' + result, s.name);
    return send(res, 200, { result, name: s.name, time_in: s.time_in, time_out: s.time_out });
  }

  if (route === 'password') {
    need(); const row = q('SELECT pass FROM users WHERE id=?').get(me.id), nw = String(b.next || '');
    if (!checkPw(String(b.current || ''), row.pass)) fail(400, 'Current password is wrong');
    if (nw.length < 10) fail(400, 'New password must be at least 10 characters');
    q('UPDATE users SET pass=? WHERE id=?').run(hashPw(nw), me.id); audit(me.username, 'changed password');
    return send(res, 200, { ok: true });
  }

  need('admin');                                    // everything below is admin only
  if (route === 'students') return send(res, 200, { students: q('SELECT code,name,grp,time_in,time_out FROM students ORDER BY name COLLATE NOCASE').all() });
  if (route === 'students/import') {
    const rows = Array.isArray(b.rows) ? b.rows.slice(0, 5000) : []; let added = 0, skipped = 0;
    db.exec('BEGIN');
    try {
      for (const r of rows) {
        const name = txt(r && r.name, 120); if (!name) { skipped++; continue; }
        let code = norm(r.code); if (code.length < 6 || q('SELECT 1 FROM students WHERE code=?').get(code)) code = genCode();
        q('INSERT INTO students(code,name,grp) VALUES(?,?,?)').run(code, name, txt(r.group, 60)); added++;
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    audit(me.username, 'import', added + ' students');
    return send(res, 200, { added, skipped });
  }
  if (route === 'students/delete') { q('DELETE FROM students WHERE code=?').run(norm(b.code)); audit(me.username, 'remove student', norm(b.code)); return send(res, 200, { ok: true }); }
  if (route === 'reset') { q('UPDATE students SET time_in=NULL,time_out=NULL,last_scan=0').run(); audit(me.username, 'reset all times'); return send(res, 200, { ok: true }); }
  if (route === 'users') return send(res, 200, { users: q('SELECT id,username,role FROM users ORDER BY username').all(), audit: q('SELECT at,who,action,detail FROM audit ORDER BY id DESC LIMIT 60').all() });
  if (route === 'users/create') {
    const u = txt(b.username, 30).toLowerCase(), pw = String(b.password || ''), role = b.role === 'admin' ? 'admin' : 'staff';
    if (!/^[a-z0-9._-]{3,30}$/.test(u)) fail(400, 'Username: 3-30 letters, numbers, . _ -');
    if (pw.length < 10) fail(400, 'Password must be at least 10 characters');
    if (q('SELECT 1 FROM users WHERE username=?').get(u)) fail(400, 'That username is taken');
    q('INSERT INTO users(username,pass,role,created) VALUES(?,?,?,?)').run(u, hashPw(pw), role, Date.now()); audit(me.username, 'create user', u + ' (' + role + ')');
    return send(res, 200, { ok: true });
  }
  if (route === 'users/delete') {
    const id = +b.id; if (id === me.id) fail(400, 'You cannot remove your own account');
    q('DELETE FROM sessions WHERE user_id=?').run(id); q('DELETE FROM users WHERE id=?').run(id); audit(me.username, 'remove user', String(id));
    return send(res, 200, { ok: true });
  }
  fail(404, 'Not found');
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/') return page(res, 'lookup.html');
    if (req.method === 'GET' && url.pathname === '/app') return page(res, 'app.html');
    if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (url.pathname.startsWith('/api/')) {
      if (req.method === 'POST') {                  // CSRF defences on top of SameSite=Strict cookies
        const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) return send(res, 403, { error: 'Bad origin' });
        if (!/^application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'JSON only' });
      } else if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });
      return await api(req, res, url.pathname.slice(5));
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'Server error' });
  }
}).listen(PORT, () => console.log('QR Attendance running on port ' + PORT));
