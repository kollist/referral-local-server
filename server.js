'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

// ── Config ────────────────────────────────────────────────────────────────────
// Must match the iOS project: RestaurantAppTemplateSwiftMarch22-1/RestaurantApp
// (APP_BUNDLE_PREFIX in project.pbxproj, DEVELOPMENT_TEAM in build settings).
const APP_BUNDLE_PREFIX = 'com.zaytech';
const TEAM_ID = 'L9KEX9UZ27';
const PUBLIC_DOMAIN = process.env.PUBLIC_DOMAIN || 'chocolate-shark-236082.hostingersite.com';

// slug -> bundle-id slug, synced from RestaurantApp/merchants.json. Only used to
// generate the apple-app-site-association file (which app+clip owns which /r/<slug>/*
// path) — nothing here is a secret.
const merchants = JSON.parse(fs.readFileSync(path.join(__dirname, 'merchants.json'), 'utf8'));

function appId(slug) {
  return `${TEAM_ID}.${APP_BUNDLE_PREFIX}.${merchants[slug]}`;
}
function clipAppId(slug) {
  return `${appId(slug)}.Clip`;
}

const AASA = {
  applinks: {
    details: Object.keys(merchants).map(slug => ({
      appIDs: [appId(slug)],
      components: [{ '/': `/r/${slug}/*` }],
    })),
  },
  appclips: {
    apps: Object.keys(merchants).map(slug => clipAppId(slug)),
  },
};

// ── DeviceCheck (fraud prevention — one reward per physical device) ─────────
// Requires a DeviceCheck-enabled key from the Apple Developer portal
// (Certificates, IDs & Profiles → Keys). Until these env vars are set, redemption
// dedup falls back to the local `redemptions` table only, which is fine for
// testing but doesn't survive a fresh reinstall the way Apple's per-device bit
// storage does.
const DEVICE_CHECK_KEY_ID = process.env.DEVICE_CHECK_KEY_ID || '';
const DEVICE_CHECK_TEAM_ID = process.env.DEVICE_CHECK_TEAM_ID || TEAM_ID;
const DEVICE_CHECK_PRIVATE_KEY = process.env.DEVICE_CHECK_PRIVATE_KEY || '';
const DEVICE_CHECK_ENABLED = Boolean(DEVICE_CHECK_KEY_ID && DEVICE_CHECK_PRIVATE_KEY);

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signDeviceCheckJWT() {
  const header = base64url(JSON.stringify({ alg: 'ES256', kid: DEVICE_CHECK_KEY_ID }));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(JSON.stringify({ iss: DEVICE_CHECK_TEAM_ID, iat: now }));
  const signingInput = `${header}.${payload}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: DEVICE_CHECK_PRIVATE_KEY,
    dsaEncoding: 'ieee-p1363', // raw r||s, required by JWS ES256 (not DER)
  });
  return `${signingInput}.${base64url(signature)}`;
}

function callDeviceCheck(pathName, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request(
      {
        hostname: 'api.devicecheck.apple.com',
        path: `/v1/${pathName}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          Authorization: `Bearer ${signDeviceCheckJWT()}`,
        },
      },
      res => {
        let chunks = '';
        res.on('data', c => (chunks += c));
        res.on('end', () => resolve({ status: res.statusCode, body: chunks }));
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Returns true if this is the first time we've seen this device_token for ANY
// merchant (bit0 unset). Sets bit0 once redeemed. Query/update are separate
// Apple endpoints; a device with bit0 already set has redeemed a referral before.
async function isFreshDevice(deviceToken) {
  const timestamp = Date.now();
  const query = await callDeviceCheck('query_two_bits', { device_token: deviceToken, transaction_id: crypto.randomUUID(), timestamp });
  let bit0 = false;
  if (query.status === 200 && query.body) {
    try { bit0 = Boolean(JSON.parse(query.body).bit0); } catch { /* Apple returns empty body when no bits are set yet */ }
  }
  if (bit0) return false;
  await callDeviceCheck('update_two_bits', { device_token: deviceToken, transaction_id: crypto.randomUUID(), timestamp, bit0: true, bit1: false });
  return true;
}

// ── Database ──────────────────────────────────────────────────────────────────

const db = new Database(path.join(__dirname, 'referral.sqlite'));
db.exec(`
  CREATE TABLE IF NOT EXISTS referral_codes (
    code          TEXT PRIMARY KEY,
    owner_token   TEXT NOT NULL,
    merchant_slug TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(owner_token, merchant_slug)
  );

  CREATE TABLE IF NOT EXISTS redemptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    referral_code TEXT NOT NULL,
    merchant_slug TEXT NOT NULL,
    device_token  TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(device_token, merchant_slug)
  );
`);

const getCodeForOwner = db.prepare(`SELECT code FROM referral_codes WHERE owner_token = ? AND merchant_slug = ?`);
const insertCode = db.prepare(`INSERT INTO referral_codes (code, owner_token, merchant_slug) VALUES (?, ?, ?)`);
const getCodeRow = db.prepare(`SELECT * FROM referral_codes WHERE code = ? AND merchant_slug = ?`);
const insertRedemption = db.prepare(`INSERT INTO redemptions (referral_code, merchant_slug, device_token) VALUES (?, ?, ?)`);
const findRedemption = db.prepare(`SELECT * FROM redemptions WHERE device_token = ? AND merchant_slug = ?`);
const recentCodes = db.prepare(`SELECT * FROM referral_codes ORDER BY rowid DESC LIMIT 50`);
const recentRedemptions = db.prepare(`SELECT * FROM redemptions ORDER BY id DESC LIMIT 50`);

function newReferralCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase(); // e.g. "A1B2C3D4"
}

// ── Express ───────────────────────────────────────────────────────────────────

const app = express();
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// apple-app-site-association — no extension, served over https, no redirect.
// Must stay under Apple's 128kb uncompressed limit (currently well under it —
// see console output at boot for the current size).
app.get('/.well-known/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});
app.get('/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});

// Fallback page for /r/:slug/:code when iOS doesn't invoke the App Clip (old
// iOS version, Android, desktop browser, or the very first tap before the
// system has cached the AASA). The App Clip itself never hits this route —
// it's launched directly from the associated domain.
app.get('/r/:slug/:code', (req, res) => {
  const { slug, code } = req.params;
  if (!merchants[slug]) {
    return res.status(404).send('Unknown merchant.');
  }
  const isAndroid = /android/i.test(req.headers['user-agent'] || '');
  res.send(`
    <html><body style="font-family: -apple-system, sans-serif; padding: 40px; text-align: center;">
      <h2>You're invited 🎉</h2>
      <p>Referral code: <code>${code}</code></p>
      <p>${isAndroid
        ? 'Install the Android app to redeem this code at signup. (Play Store link goes here — add the merchant\'s package name once the Android app exists.)'
        : 'Install the app to redeem this code automatically — or open it now if you already have it.'}</p>
    </body></html>
  `);
});

// ── App Clip-facing endpoints ─────────────────────────────────────────────────

// GET /api/referral/:slug/:code — the App Clip calls this to render its invite
// card. No fingerprinting involved: the code came straight from the invocation
// URL, so this is an exact lookup.
app.get('/api/referral/:slug/:code', (req, res) => {
  const { slug, code } = req.params;
  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_merchant' });
  }
  const row = getCodeRow.get(code, slug);
  if (!row) {
    return res.status(404).json({ error: 'unknown_code' });
  }
  res.json({ merchant_slug: slug, referral_code: row.code });
});

// POST /guests/redeem-referral — called once by the FULL app on first launch,
// after it picks up the referral code from the NSUserActivity handoff (or from
// a manually-entered code, if the user typed it in). Exact match, no fingerprint
// guessing: the code is either valid for this merchant or it isn't.
//
// device_token should be a DCDevice.current.generateToken() token from the app.
// Falls back to local-only dedup (by device_token string) if DeviceCheck env
// vars aren't configured yet — fine for testing, not fraud-proof for production.
app.post('/guests/redeem-referral', async (req, res) => {
  const { merchant_slug, referral_code, device_token } = req.body || {};
  if (!merchant_slug || !referral_code || !device_token) {
    return res.status(400).json({ error: 'merchant_slug, referral_code and device_token are required' });
  }
  if (!merchants[merchant_slug]) {
    return res.status(404).json({ error: 'unknown_merchant' });
  }

  const row = getCodeRow.get(referral_code, merchant_slug);
  if (!row) {
    return res.status(404).json({ error: 'unknown_code' });
  }

  if (findRedemption.get(device_token, merchant_slug)) {
    return res.status(409).json({ error: 'already_redeemed' });
  }

  if (DEVICE_CHECK_ENABLED) {
    try {
      const fresh = await isFreshDevice(device_token);
      if (!fresh) {
        return res.status(409).json({ error: 'device_already_rewarded' });
      }
    } catch (err) {
      console.error('DeviceCheck call failed:', err.message);
      return res.status(502).json({ error: 'device_check_unavailable' });
    }
  }

  insertRedemption.run(referral_code, merchant_slug, device_token);
  res.json({ ok: true, merchant_slug, referral_code });
});

// GET /customers/referral?merchant=<slug> — Invite Friends screen. Any bearer
// token works here; it's a stand-in for "which logged-in user."
app.get('/customers/referral', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  const slug = req.query.merchant;
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }
  if (!slug || !merchants[slug]) {
    return res.status(400).json({ error: 'Missing or unknown ?merchant=<slug>' });
  }

  let row = getCodeForOwner.get(token, slug);
  let code;
  if (row) {
    code = row.code;
  } else {
    code = newReferralCode();
    insertCode.run(code, token, slug);
  }

  res.json({
    referral_code: code,
    referral_link: `https://${PUBLIC_DOMAIN}/r/${slug}/${code}`,
  });
});

// ── Dashboard API ─────────────────────────────────────────────────────────────

app.get('/api/state', (req, res) => {
  res.json({
    codes: recentCodes.all(),
    redemptions: recentRedemptions.all(),
    device_check_enabled: DEVICE_CHECK_ENABLED,
    merchant_count: Object.keys(merchants).length,
  });
});

app.post('/debug/reset', (req, res) => {
  db.exec('DELETE FROM referral_codes; DELETE FROM redemptions;');
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4001;
app.listen(PORT, '0.0.0.0', () => {
  const aasaSize = Buffer.byteLength(JSON.stringify(AASA));
  console.log(`\n🔗 Referral server running`);
  console.log(`   Dashboard:        http://localhost:${PORT}`);
  console.log(`   Public domain:    https://${PUBLIC_DOMAIN}`);
  console.log(`   Merchants loaded: ${Object.keys(merchants).length} (AASA size: ${aasaSize} bytes / 128000 max)`);
  console.log(`   DeviceCheck:      ${DEVICE_CHECK_ENABLED ? 'enabled' : 'disabled (local-only dedup)'}`);
  console.log(`   Referral lookup:  GET  http://localhost:${PORT}/api/referral/:slug/:code`);
  console.log(`   Redeem:           POST http://localhost:${PORT}/guests/redeem-referral`);
  console.log(`   Referral info:    GET  http://localhost:${PORT}/customers/referral?merchant=:slug\n`);
});
