'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

// ── Database setup ────────────────────────────────────────────────────────────

const db = new Database(path.join(__dirname, 'referral.sqlite'));

db.exec(`
  CREATE TABLE IF NOT EXISTS clicks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    referral_code TEXT NOT NULL,
    ip            TEXT NOT NULL,
    user_agent    TEXT,
    screen_width  INTEGER,
    screen_height INTEGER,
    timezone      TEXT,
    consumed      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS codes (
    token         TEXT PRIMARY KEY,
    referral_code TEXT UNIQUE NOT NULL,
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ip);
`);

// Matching window: how long a click stays eligible to be matched to a fresh install.
// Generous for manual testing — the real backend should use something tighter (15-60 min).
const MATCH_WINDOW_MINUTES = 60;

// Screen dimensions are compared with a little slack (points vs pixels, rounding
// differences between what a browser reports and what the app measures).
const SCREEN_TOLERANCE = 8;

const insertClick = db.prepare(`
  INSERT INTO clicks (referral_code, ip, user_agent, screen_width, screen_height, timezone)
  VALUES (@referral_code, @ip, @user_agent, @screen_width, @screen_height, @timezone)
`);

const withinWindow = `created_at > datetime('now', '-${MATCH_WINDOW_MINUTES} minutes')`;

// Tier 1: IP + screen size + timezone all agree — highest confidence.
const findStrongMatch = db.prepare(`
  SELECT * FROM clicks
  WHERE ip = @ip AND consumed = 0 AND ${withinWindow}
    AND screen_width IS NOT NULL AND ABS(screen_width - @screen_width) <= ${SCREEN_TOLERANCE}
    AND screen_height IS NOT NULL AND ABS(screen_height - @screen_height) <= ${SCREEN_TOLERANCE}
    AND timezone IS NOT NULL AND timezone = @timezone
  ORDER BY created_at DESC LIMIT 1
`);

// Tier 2: IP + at least one of screen size / timezone agrees.
const findMediumMatch = db.prepare(`
  SELECT * FROM clicks
  WHERE ip = @ip AND consumed = 0 AND ${withinWindow}
    AND (
      (screen_width IS NOT NULL AND ABS(screen_width - @screen_width) <= ${SCREEN_TOLERANCE}
        AND screen_height IS NOT NULL AND ABS(screen_height - @screen_height) <= ${SCREEN_TOLERANCE})
      OR (timezone IS NOT NULL AND timezone = @timezone)
    )
  ORDER BY created_at DESC LIMIT 1
`);

// Tier 3: IP only — the fallback we started with, used when the landing page
// couldn't capture screen/timezone (e.g. JS blocked, or an older cached page).
const findWeakMatch = db.prepare(`
  SELECT * FROM clicks
  WHERE ip = @ip AND consumed = 0 AND ${withinWindow}
  ORDER BY created_at DESC LIMIT 1
`);

const consumeClick = db.prepare(`UPDATE clicks SET consumed = 1 WHERE id = ?`);
const recentClicks = db.prepare(`SELECT * FROM clicks ORDER BY id DESC LIMIT 50`);

const getCodeForToken = db.prepare(`SELECT referral_code FROM codes WHERE token = ?`);
const insertCodeForToken = db.prepare(`INSERT INTO codes (token, referral_code) VALUES (?, ?)`);
const recentCodes = db.prepare(`SELECT * FROM codes ORDER BY rowid DESC LIMIT 50`);

function normalizeIp(ip) {
  // Express reports IPv4 clients as ::ffff:a.b.c.d when the server listens on 0.0.0.0.
  return (ip || '').replace(/^::ffff:/, '');
}

function newReferralCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase(); // e.g. "A1B2C3D4"
}

function findMatch(params) {
  const hasSignals = params.screen_width != null && params.screen_height != null && params.timezone;
  if (hasSignals) {
    return findStrongMatch.get(params) || findMediumMatch.get(params) || findWeakMatch.get(params);
  }
  return findWeakMatch.get(params);
}

// ── Express ───────────────────────────────────────────────────────────────────

const app = express();
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path} from ${normalizeIp(req.ip)}`);
  next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Simulated landing page ───────────────────────────────────────────────────
// Stand-in for the real hosted invite page (not built yet). Visiting this URL is
// what tapping a shared invite link does. The page itself captures screen size +
// timezone via JS (a server can't see those from the request alone) and posts
// them to /r/:code/log, which is what actually records the click. Open it in
// Safari on the SAME device you'll then launch the app on, so the signals line up.

app.get('/r/:code', (req, res) => {
  const code = req.params.code;
  res.send(`
    <html><body style="font-family: -apple-system, sans-serif; padding: 40px; text-align: center;">
      <h2 id="status">Recording click…</h2>
      <p>In production this page would then redirect to the App Store.<br>
      For testing: once recorded, launch (or relaunch) the app on <b>this same device</b>
      within ${MATCH_WINDOW_MINUTES} minutes.</p>
      <script>
        fetch('/r/${code}/log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            screen_width: Math.round(screen.width * (window.devicePixelRatio || 1)),
            screen_height: Math.round(screen.height * (window.devicePixelRatio || 1)),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          }),
        })
          .then(r => r.json())
          .then(() => { document.getElementById('status').textContent = 'Click recorded ✅'; })
          .catch(() => { document.getElementById('status').textContent = 'Could not record click ❌'; });
      </script>
    </body></html>
  `);
});

app.post('/r/:code/log', (req, res) => {
  const code = req.params.code;
  const ip = normalizeIp(req.ip);
  const { screen_width, screen_height, timezone } = req.body || {};
  insertClick.run({
    referral_code: code,
    ip,
    user_agent: req.headers['user-agent'] || null,
    screen_width: screen_width ?? null,
    screen_height: screen_height ?? null,
    timezone: timezone ?? null,
  });
  res.json({ ok: true });
});

// ── App-facing endpoints (match SOOEndPoint.swift) ───────────────────────────

// POST /guests/check-referral-attribution — called once on first app launch.
// Matches by IP, using screen size + timezone (also sent by the app) as extra
// confidence signals when more than one recent click shares the same IP.
app.post('/guests/check-referral-attribution', (req, res) => {
  const ip = normalizeIp(req.ip);
  const { screen_width, screen_height, timezone } = req.body || {};
  const click = findMatch({ ip, screen_width: screen_width ?? null, screen_height: screen_height ?? null, timezone: timezone ?? null });
  if (!click) {
    return res.json({ referral_code: null });
  }
  consumeClick.run(click.id);
  res.json({ referral_code: click.referral_code });
});

// GET /customers/referral — called from the Invite Friends screen. Any bearer
// token works here; the token is just used as a stable stand-in for "which user."
app.get('/customers/referral', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  let row = getCodeForToken.get(token);
  if (!row) {
    const code = newReferralCode();
    insertCodeForToken.run(token, code);
    row = { referral_code: code };
  }

  const host = req.get('host'); // e.g. 192.168.1.15:4001
  res.json({
    referral_code: row.referral_code,
    referral_link: `http://${host}/r/${row.referral_code}`,
  });
});

// ── Dashboard API ─────────────────────────────────────────────────────────────

app.get('/api/state', (req, res) => {
  res.json({
    clicks: recentClicks.all(),
    codes: recentCodes.all(),
  });
});

app.post('/debug/reset', (req, res) => {
  db.exec('DELETE FROM clicks; DELETE FROM codes;');
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔗 Referral local server running`);
  console.log(`   Dashboard:      http://localhost:${PORT}`);
  console.log(`   Attribution:    POST http://localhost:${PORT}/guests/check-referral-attribution`);
  console.log(`   Referral info:  GET  http://localhost:${PORT}/customers/referral`);
  console.log(`   Simulated link: GET  http://localhost:${PORT}/r/:code\n`);
});
