require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const GROUP_ID = String(process.env.ROBLOX_GROUP_ID || '616609542');
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const db = new Database(path.join(__dirname, 'greenbasket.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS staff (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Staff', is_owner INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, provider_id TEXT NOT NULL,
 username TEXT NOT NULL, department TEXT NOT NULL, answers TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// Bootstrap owner once. Never place credentials in frontend files.
(async () => {
  const email = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
  const password = process.env.OWNER_PASSWORD || '';
  if (email && password && !db.prepare('SELECT id FROM staff WHERE is_owner=1').get()) {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO staff (email,password_hash,display_name,role,is_owner) VALUES (?,?,?,?,1)')
      .run(email, hash, process.env.OWNER_DISPLAY_NAME || 'GreenBasket Owner', 'Owner');
    console.log('GreenBasket owner account created from environment settings.');
  }
})();

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false })); // Add a strict CSP when deploying your final hosted version.
app.use(express.urlencoded({ extended: false, limit: '30kb' }));
app.use(express.json({ limit: '30kb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'development-only-change-this-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });

function requireStaff(req, res, next) {
  if (!req.session.staff) return res.status(401).json({ error: 'Please sign in with your staff account.' });
  next();
}
function requireOwner(req, res, next) {
  if (!req.session.staff || !req.session.staff.isOwner) return res.status(403).json({ error: 'Owner permission required.' });
  next();
}
function csrf(req, res, next) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  res.locals.csrf = req.session.csrf;
  next();
}
app.use(csrf);
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && !['GET','HEAD','OPTIONS'].includes(req.method)) {
    const supplied = req.get('x-csrf-token');
    if (!supplied || supplied !== req.session.csrf) return res.status(403).json({ error: 'Session security token expired. Refresh the page and try again.' });
  }
  next();
});
app.get('/api/config', (req, res) => res.json({ groupId: GROUP_ID, signedIn: !!req.session.applicant, applicant: req.session.applicant || null, staff: req.session.staff || null, csrf: req.session.csrf }));
app.get('/api/policies/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/api/policies/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));

// Staff email/password authentication. Staff are provisioned only by owner routes below.
app.post('/api/staff/login', loginLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const staff = db.prepare('SELECT * FROM staff WHERE email=?').get(email);
  if (!staff || !(await bcrypt.compare(password, staff.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  req.session.staff = { id: staff.id, email: staff.email, displayName: staff.display_name, role: staff.role, isOwner: !!staff.is_owner };
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Could not start secure session.' });
    req.session.staff = { id: staff.id, email: staff.email, displayName: staff.display_name, role: staff.role, isOwner: !!staff.is_owner };
    req.session.csrf = crypto.randomBytes(32).toString('hex');
    res.json({ ok: true, staff: req.session.staff, csrf: req.session.csrf });
  });
});
app.post('/api/staff/logout', requireStaff, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/staff/me', requireStaff, (req, res) => res.json(req.session.staff));

// Owner-only account management: create, update email/role/password, remove.
app.get('/api/staff/accounts', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT id,email,display_name,role,is_owner,created_at FROM staff ORDER BY is_owner DESC,id').all();
  res.json(rows);
});
app.post('/api/staff/accounts', requireOwner, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');
  const role = String(req.body.role || 'Staff').trim().slice(0, 40);
  if (!email.includes('@') || !displayName || password.length < 12) return res.status(400).json({ error: 'Enter a valid email, display name and password of at least 12 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO staff (email,password_hash,display_name,role,is_owner) VALUES (?,?,?,?,0)').run(email, hash, displayName, role);
    res.json({ ok: true, id: result.lastInsertRowid });
  } catch { res.status(409).json({ error: 'That email is already in use.' }); }
});
app.patch('/api/staff/accounts/:id', requireOwner, async (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare('SELECT * FROM staff WHERE id=?').get(id);
  if (!target || target.is_owner) return res.status(400).json({ error: 'Owner account cannot be changed here.' });
  const email = req.body.email === undefined ? target.email : String(req.body.email).trim().toLowerCase();
  const displayName = req.body.displayName === undefined ? target.display_name : String(req.body.displayName).trim();
  const role = req.body.role === undefined ? target.role : String(req.body.role).trim().slice(0, 40);
  try {
    if (req.body.password) {
      if (String(req.body.password).length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters.' });
      const hash = await bcrypt.hash(String(req.body.password), 12);
      db.prepare('UPDATE staff SET email=?,display_name=?,role=?,password_hash=? WHERE id=?').run(email, displayName, role, hash, id);
    } else db.prepare('UPDATE staff SET email=?,display_name=?,role=? WHERE id=?').run(email, displayName, role, id);
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'That email is already in use.' }); }
});
app.delete('/api/staff/accounts/:id', requireOwner, (req, res) => {
  const target = db.prepare('SELECT * FROM staff WHERE id=?').get(Number(req.params.id));
  if (!target || target.is_owner) return res.status(400).json({ error: 'Owner account cannot be removed.' });
  db.prepare('DELETE FROM staff WHERE id=?').run(target.id);
  res.json({ ok: true });
});

// Application submission and staff review.
app.post('/api/applications', (req, res) => {
  const user = req.session.applicant;
  if (!user) return res.status(401).json({ error: 'Log in with Roblox or Discord before applying.' });
  const department = String(req.body.department || '').trim();
  const allowed = ['Store Colleague', 'Security'];
  if (!allowed.includes(department)) return res.status(400).json({ error: 'Choose a valid department.' });
  const answers = {};
  ['why','benefit','scenario'].forEach(k => answers[k] = String(req.body[k] || '').trim().slice(0, 2000));
  if (Object.values(answers).some(v => v.length < 10)) return res.status(400).json({ error: 'Please answer each question with at least 10 characters.' });
  db.prepare('INSERT INTO applications (provider,provider_id,username,department,answers) VALUES (?,?,?,?,?)')
    .run(user.provider, user.id, user.username, department, JSON.stringify(answers));
  res.json({ ok: true, message: 'Your application has been submitted.' });
});
app.get('/api/staff/applications', requireStaff, (req, res) => {
  const rows = db.prepare('SELECT * FROM applications ORDER BY created_at DESC').all().map(r => ({ ...r, answers: JSON.parse(r.answers) }));
  res.json(rows);
});
app.patch('/api/staff/applications/:id', requireStaff, (req, res) => {
  const status = String(req.body.status || '');
  if (!['Pending','Under Review','Accepted','Declined'].includes(status)) return res.status(400).json({ error: 'Invalid application status.' });
  db.prepare('UPDATE applications SET status=? WHERE id=?').run(status, Number(req.params.id));
  res.json({ ok: true });
});

// OAuth state helpers. State is one-use and stored in the server session.
function setOAuthState(req, provider) { const state = crypto.randomBytes(24).toString('hex'); req.session.oauthState = { provider, state }; return state; }
function validOAuthState(req, provider, state) { const saved = req.session.oauthState; req.session.oauthState = null; return !!saved && saved.provider === provider && saved.state === state; }
app.get('/auth/roblox', (req, res) => {
  if (!process.env.ROBLOX_CLIENT_ID || !process.env.ROBLOX_CLIENT_SECRET) return res.status(503).send('Roblox OAuth is not configured yet. Add the credentials to your server .env file.');
  const state = setOAuthState(req, 'roblox');
  const params = new URLSearchParams({ client_id: process.env.ROBLOX_CLIENT_ID, redirect_uri: process.env.ROBLOX_REDIRECT_URI, scope: 'openid profile', response_type: 'code', state });
  res.redirect('https://apis.roblox.com/oauth/v1/authorize?' + params.toString());
});
app.get('/auth/roblox/callback', async (req, res) => {
  if (req.query.error || !validOAuthState(req, 'roblox', String(req.query.state || ''))) return res.redirect('/?auth=failed');
  try {
    const body = new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code || ''), client_id: process.env.ROBLOX_CLIENT_ID, client_secret: process.env.ROBLOX_CLIENT_SECRET, redirect_uri: process.env.ROBLOX_REDIRECT_URI });
    const tokenResponse = await fetch('https://apis.roblox.com/oauth/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    const token = await tokenResponse.json(); if (!tokenResponse.ok) throw new Error('Roblox token exchange failed');
    const profileResponse = await fetch('https://apis.roblox.com/oauth/v1/userinfo', { headers: { Authorization: `Bearer ${token.access_token}` } });
    const profile = await profileResponse.json(); if (!profileResponse.ok || !profile.sub) throw new Error('Roblox profile lookup failed');
    req.session.applicant = { provider: 'Roblox', id: String(profile.sub), username: profile.preferred_username || profile.nickname || profile.name || 'Roblox User' };
    res.redirect('/?auth=success');
  } catch (e) { console.error(e.message); res.redirect('/?auth=failed'); }
});
app.get('/auth/discord', (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET) return res.status(503).send('Discord OAuth is not configured yet. Add the credentials to your server .env file.');
  const state = setOAuthState(req, 'discord');
  const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, redirect_uri: process.env.DISCORD_REDIRECT_URI, response_type: 'code', scope: 'identify', state });
  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});
app.get('/auth/discord/callback', async (req, res) => {
  if (req.query.error || !validOAuthState(req, 'discord', String(req.query.state || ''))) return res.redirect('/?auth=failed');
  try {
    const body = new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code || ''), client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, redirect_uri: process.env.DISCORD_REDIRECT_URI });
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    const token = await tokenResponse.json(); if (!tokenResponse.ok) throw new Error('Discord token exchange failed');
    const profileResponse = await fetch('https://discord.com/api/v10/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } });
    const profile = await profileResponse.json(); if (!profileResponse.ok || !profile.id) throw new Error('Discord profile lookup failed');
    req.session.applicant = { provider: 'Discord', id: String(profile.id), username: profile.global_name || profile.username || 'Discord User' };
    res.redirect('/?auth=success');
  } catch (e) { console.error(e.message); res.redirect('/?auth=failed'); }
});
app.post('/api/applicant/logout', (req, res) => { req.session.applicant = null; res.json({ ok: true }); });

app.get('/health', (_, res) => res.json({ ok: true, service: 'GreenBasket website' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) console.warn('WARNING: Set SESSION_SECRET to a random string of 32+ characters before deployment.');
app.listen(PORT, () => console.log(`GreenBasket website running at ${BASE_URL}`));
