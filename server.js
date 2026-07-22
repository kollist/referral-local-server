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

// Fingerprint match window for the iOS fallback (no App Clip / no recovered
// code) — 48h, same as documented for the real backend's IP+language match.
const MATCH_WINDOW_HOURS = 48;
// Screen dimensions are compared with a little slack — browser-reported vs
// native-reported pixel values don't always agree exactly (devicePixelRatio
// rounding, status bar inclusion, etc.).
const SCREEN_TOLERANCE = 8;

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

// ── Referral settings — live from the real sandbox backend ───────────────────
// Fetched from the actual API (no auth required for this endpoint), not a
// local mirror that can drift out of sync. Falls back to sensible test values
// for slugs that don't exist there (our merchants.json has 464 fake test
// merchants; only real ones like vccsandbox actually resolve).
const SETTINGS_API_BASE = process.env.SETTINGS_API_BASE || 'https://api-v2-sandbox.smartonlineorders.com';
const SETTINGS_CACHE_TTL_MS = 60_000;
const settingsCache = new Map(); // slug -> { value, expiresAt }

const DEFAULT_REFERRAL_SETTINGS = {
  enabled: true,
  referrer: { type: 'referral_referrer', is_active: true, get: 'points', nb_points: 50 },
  referee: { type: 'referral_referee', is_active: true, get: 'discount', discount_type: 'amount', discount_amount: 500, discount_max_amount: null, discount_min_amount: null },
  order: null,
};

async function settingsFor(slug) {
  const cached = settingsCache.get(slug);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  let value = DEFAULT_REFERRAL_SETTINGS;
  try {
    const res = await fetch(`${SETTINGS_API_BASE}/v2/group-merchants/${encodeURIComponent(slug)}`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.settings && data.settings.referral) {
        value = data.settings.referral;
      }
    }
  } catch (err) {
    console.error(`settingsFor(${slug}): live fetch failed, using default —`, err.message);
  }

  settingsCache.set(slug, { value, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
  return value;
}

// ── DeviceCheck (backup fraud check, alongside x-soo-device-id) ──────────────
// x-soo-device-id is a client-generated string (e.g. a Keychain-persisted
// UUID) — trivially reset by clearing app data. DeviceCheck's two-bit state is
// Apple-verified and survives that, so we run it as a second check when the
// app sends a token, without requiring it (mirrors the real claim contract,
// which has no DeviceCheck field of its own).
const DEVICE_CHECK_KEY_ID = process.env.DEVICE_CHECK_KEY_ID || '';
const DEVICE_CHECK_TEAM_ID = process.env.DEVICE_CHECK_TEAM_ID || TEAM_ID;
const DEVICE_CHECK_PRIVATE_KEY = process.env.DEVICE_CHECK_PRIVATE_KEY_PATH
  ? fs.readFileSync(process.env.DEVICE_CHECK_PRIVATE_KEY_PATH, 'utf8')
  : (process.env.DEVICE_CHECK_PRIVATE_KEY || '');
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

// Returns true if this is the first time we've seen this device_token (bit0
// unset), and marks it used. Throws on any non-200 from Apple — a malformed
// token must reject, not silently pass as "fresh."
async function isFreshDevice(deviceToken) {
  const timestamp = Date.now();
  const query = await callDeviceCheck('query_two_bits', { device_token: deviceToken, transaction_id: crypto.randomUUID(), timestamp });
  if (query.status !== 200) {
    throw new Error(`DeviceCheck query_two_bits rejected the token: HTTP ${query.status} ${query.body}`);
  }
  let bit0 = false;
  if (query.body) {
    bit0 = Boolean(JSON.parse(query.body).bit0);
  }
  if (bit0) return false;

  const update = await callDeviceCheck('update_two_bits', { device_token: deviceToken, transaction_id: crypto.randomUUID(), timestamp, bit0: true, bit1: false });
  if (update.status !== 200) {
    throw new Error(`DeviceCheck update_two_bits failed: HTTP ${update.status} ${update.body}`);
  }
  return true;
}

// ── Code generation ───────────────────────────────────────────────────────────
// Unambiguous alphabet per the real backend's spec: no O/0, I/1, L.
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function newReferralCode() {
  return Array.from(crypto.randomBytes(8))
    .map(b => CODE_ALPHABET[b % CODE_ALPHABET.length])
    .join('');
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex');
}
function normalizeIp(ip) {
  return (ip || '').replace(/^::ffff:/, '');
}
function platformFromUserAgent(ua) {
  if (/android/i.test(ua || '')) return 'android';
  if (/iphone|ipad|ipod|cfnetwork|darwin/i.test(ua || '')) return 'ios';
  return 'other';
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

  -- One row per landing-page visit (JS-measured screen size posted back after
  -- the initial GET). Powers the iOS fingerprint fallback: hashed IP +
  -- platform + Accept-Language + screen size.
  CREATE TABLE IF NOT EXISTS clicks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    code            TEXT NOT NULL,
    merchant_slug   TEXT NOT NULL,
    ip_hash         TEXT NOT NULL,
    platform        TEXT NOT NULL,
    accept_language TEXT,
    screen_width    INTEGER,
    screen_height   INTEGER,
    consumed        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_clicks_match ON clicks(merchant_slug, ip_hash, platform, accept_language, consumed);

  CREATE TABLE IF NOT EXISTS claims (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_slug  TEXT NOT NULL,
    customer_token TEXT NOT NULL,
    device_id      TEXT,
    referral_code  TEXT NOT NULL,
    matched_via    TEXT NOT NULL, -- 'code' | 'fingerprint'
    created_at     TEXT DEFAULT (datetime('now')),
    UNIQUE(merchant_slug, customer_token)
  );
`);

const getCodeForOwner = db.prepare(`SELECT code FROM referral_codes WHERE owner_token = ? AND merchant_slug = ?`);
const insertCode = db.prepare(`INSERT INTO referral_codes (code, owner_token, merchant_slug) VALUES (?, ?, ?)`);
const getCodeRow = db.prepare(`SELECT * FROM referral_codes WHERE code = ? AND merchant_slug = ?`);
const recentCodes = db.prepare(`SELECT * FROM referral_codes ORDER BY rowid DESC LIMIT 50`);

const insertClick = db.prepare(`
  INSERT INTO clicks (code, merchant_slug, ip_hash, platform, accept_language, screen_width, screen_height)
  VALUES (@code, @merchant_slug, @ip_hash, @platform, @accept_language, @screen_width, @screen_height)
`);
const recentClicks = db.prepare(`SELECT * FROM clicks ORDER BY id DESC LIMIT 50`);
// Base filter on the exact signals (IP + platform + language); screen size is
// checked in JS afterward with tolerance, since SQL abs() range checks would
// need to special-case "not provided" on both sides anyway.
const findFingerprintCandidates = db.prepare(`
  SELECT * FROM clicks
  WHERE merchant_slug = @merchant_slug
    AND ip_hash = @ip_hash
    AND platform = @platform
    AND accept_language = @accept_language
    AND consumed = 0
    AND created_at > datetime('now', '-${MATCH_WINDOW_HOURS} hours')
  ORDER BY created_at DESC
`);
const consumeClick = db.prepare(`UPDATE clicks SET consumed = 1 WHERE id = ?`);

const getClaimForCustomer = db.prepare(`SELECT * FROM claims WHERE merchant_slug = ? AND customer_token = ?`);
const findClaimByDevice = db.prepare(`SELECT * FROM claims WHERE merchant_slug = ? AND device_id = ? AND device_id IS NOT NULL AND device_id != ''`);
const insertClaim = db.prepare(`
  INSERT INTO claims (merchant_slug, customer_token, device_id, referral_code, matched_via)
  VALUES (@merchant_slug, @customer_token, @device_id, @referral_code, @matched_via)
`);
const recentClaims = db.prepare(`SELECT * FROM claims ORDER BY id DESC LIMIT 50`);

function findFingerprintMatch({ merchant_slug, ip_hash, platform, accept_language, screen_width, screen_height }) {
  const candidates = findFingerprintCandidates.all({ merchant_slug, ip_hash, platform, accept_language });
  const hasClaimScreen = screen_width != null && screen_height != null;
  for (const click of candidates) {
    const hasClickScreen = click.screen_width != null && click.screen_height != null;
    if (hasClaimScreen && hasClickScreen) {
      const widthOk = Math.abs(click.screen_width - screen_width) <= SCREEN_TOLERANCE;
      const heightOk = Math.abs(click.screen_height - screen_height) <= SCREEN_TOLERANCE;
      if (!widthOk || !heightOk) continue; // screen size disagrees — not this click
    }
    return click; // either both sides have screen data and it matches, or one side lacks it (best effort)
  }
  return null;
}

// ── Express ───────────────────────────────────────────────────────────────────

const app = express();
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function bearerToken(req) {
  return (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();
}

app.get('/.well-known/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});
app.get('/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});

// GET /r/:slug/:code — the actual tapped link.
//   Android: redirect immediately with &referrer=code (exact match, no need
//   for a fingerprint — same as before).
//   iOS/other: the App Clip normally launches directly and never hits this
//   route at all. This path is only exercised as a fallback (old iOS, no App
//   Clip support, desktop browser) — so it shows a tiny interstitial that
//   measures screen size via JS, posts it back, then redirects. That's the
//   only way to get screen size server-side; a plain redirect can't run JS.
app.get('/r/:slug/:code', (req, res) => {
  const { slug, code } = req.params;
  if (!merchants[slug]) {
    return res.status(404).send('Unknown merchant.');
  }
  const platform = platformFromUserAgent(req.headers['user-agent']);

  if (platform === 'android') {
    insertClick.run({
      code, merchant_slug: slug,
      ip_hash: hashIp(normalizeIp(req.ip)), platform, accept_language: req.headers['accept-language'] || null,
      screen_width: null, screen_height: null,
    });
    return res.redirect(`https://play.google.com/store/apps/details?id=${APP_BUNDLE_PREFIX}.${merchants[slug]}&referrer=${encodeURIComponent(code)}`);
  }

  const appStoreUrl = `https://apps.apple.com/app/${APP_BUNDLE_PREFIX}.${merchants[slug]}`;
  res.send(`
    <html><body style="font-family: -apple-system, sans-serif; padding: 40px; text-align: center;">
      <p>Redirecting…</p>
      <script>
        fetch('/r/${slug}/${code}/log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            screen_width: Math.round(screen.width * (window.devicePixelRatio || 1)),
            screen_height: Math.round(screen.height * (window.devicePixelRatio || 1)),
          }),
        }).finally(() => { window.location.href = '${appStoreUrl}'; });
      </script>
    </body></html>
  `);
});

app.post('/r/:slug/:code/log', (req, res) => {
  const { slug, code } = req.params;
  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_merchant' });
  }
  const { screen_width, screen_height } = req.body || {};
  insertClick.run({
    code, merchant_slug: slug,
    ip_hash: hashIp(normalizeIp(req.ip)),
    platform: platformFromUserAgent(req.headers['user-agent']),
    accept_language: req.headers['accept-language'] || null,
    screen_width: screen_width ?? null,
    screen_height: screen_height ?? null,
  });
  res.json({ ok: true });
});

// ── Real API contract ─────────────────────────────────────────────────────────

app.get('/v2/group-merchants/:slug', async (req, res) => {
  const { slug } = req.params;
  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_slug' });
  }
  res.json({ settings: { referral: await settingsFor(slug) } });
});

app.get('/v2/group-merchants/:slug/customers/referral', (req, res) => {
  const { slug } = req.params;
  const token = bearerToken(req);
  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_slug' });
  }
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
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
    code,
    share_url: `https://${PUBLIC_DOMAIN}/r/${slug}/${code}`,
  });
});

// POST /v2/group-merchants/:slug/customers/referrals/claim
// Body may include screen_width/screen_height and device_check_token — both
// are extensions beyond the documented contract, used only to strengthen this
// test double's fingerprint fallback and add a DeviceCheck backup check. They
// won't exist when this is swapped for the real backend; the exact-code and
// IP+platform+language paths are what carries over unchanged.
app.post('/v2/group-merchants/:slug/customers/referrals/claim', async (req, res) => {
  const { slug } = req.params;
  const token = bearerToken(req);
  const deviceId = req.headers['x-soo-device-id'] || '';
  const acceptLanguage = req.headers['accept-language'] || null;
  const { referral_code, screen_width, screen_height, device_check_token } = req.body || {};

  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_slug' });
  }
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const settings = await settingsFor(slug);
    if (!settings.enabled) {
      return res.json({ attributed: false, reason: 'program_inactive' });
    }

    if (getClaimForCustomer.get(slug, token)) {
      return res.json({ attributed: false, reason: 'already_referred' });
    }

    if (deviceId && findClaimByDevice.get(slug, deviceId)) {
      return res.json({ attributed: false, reason: 'device_used' });
    }

    // DeviceCheck backup: only runs if the app sent a token. x-soo-device-id
    // is the primary check above; this catches the case where that string
    // was reset (reinstall, cleared Keychain) but the physical device is the
    // same one, which Apple's per-device bits still remember.
    if (DEVICE_CHECK_ENABLED && device_check_token) {
      try {
        const fresh = await isFreshDevice(device_check_token);
        if (!fresh) {
          return res.json({ attributed: false, reason: 'device_used' });
        }
      } catch (err) {
        console.error('DeviceCheck backup check failed (non-fatal, continuing on x-soo-device-id alone):', err.message);
      }
    }

    if (referral_code) {
      const codeRow = getCodeRow.get(referral_code, slug);
      if (!codeRow) {
        return res.json({ attributed: false, reason: 'wrong_group' });
      }
      if (codeRow.owner_token === token) {
        return res.json({ attributed: false, reason: 'self_referral' });
      }
      insertClaim.run({ merchant_slug: slug, customer_token: token, device_id: deviceId || null, referral_code, matched_via: 'code' });
      return res.json({ attributed: true });
    }

    // No code — iOS fingerprint fallback (IP + platform + language, plus
    // screen size when both sides report it).
    const match = findFingerprintMatch({
      merchant_slug: slug,
      ip_hash: hashIp(normalizeIp(req.ip)),
      platform: platformFromUserAgent(req.headers['user-agent']),
      accept_language: acceptLanguage,
      screen_width: screen_width ?? null,
      screen_height: screen_height ?? null,
    });
    if (!match) {
      return res.json({ attributed: false, reason: 'no_match' });
    }
    const codeRow = getCodeRow.get(match.code, slug);
    if (codeRow && codeRow.owner_token === token) {
      return res.json({ attributed: false, reason: 'self_referral' });
    }
    consumeClick.run(match.id);
    insertClaim.run({ merchant_slug: slug, customer_token: token, device_id: deviceId || null, referral_code: match.code, matched_via: 'fingerprint' });
    return res.json({ attributed: true });
  } catch (err) {
    console.error('claim failed:', err.message);
    return res.json({ attributed: false, reason: 'error' });
  }
});

// ── Dashboard API ─────────────────────────────────────────────────────────────

app.get('/api/state', (req, res) => {
  res.json({
    codes: recentCodes.all(),
    clicks: recentClicks.all(),
    claims: recentClaims.all(),
    merchant_count: Object.keys(merchants).length,
    device_check_enabled: DEVICE_CHECK_ENABLED,
    settings_api_base: SETTINGS_API_BASE,
  });
});

app.post('/debug/reset', (req, res) => {
  db.exec('DELETE FROM referral_codes; DELETE FROM clicks; DELETE FROM claims;');
  settingsCache.clear();
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4001;
app.listen(PORT, '0.0.0.0', () => {
  const aasaSize = Buffer.byteLength(JSON.stringify(AASA));
  console.log(`\n🔗 Referral server running (mirrors /v2/group-merchants/{slug}/... contract)`);
  console.log(`   Dashboard:        http://localhost:${PORT}`);
  console.log(`   Public domain:    https://${PUBLIC_DOMAIN}`);
  console.log(`   Settings source:  ${SETTINGS_API_BASE} (live, cached ${SETTINGS_CACHE_TTL_MS / 1000}s, default fallback)`);
  console.log(`   Merchants loaded: ${Object.keys(merchants).length} (AASA size: ${aasaSize} bytes / 128000 max)`);
  console.log(`   DeviceCheck:      ${DEVICE_CHECK_ENABLED ? 'enabled (backup check)' : 'disabled'}\n`);
});
