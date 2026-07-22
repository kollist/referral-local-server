'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────
// Must match the iOS project: RestaurantAppTemplateSwiftMarch22-1/RestaurantApp
// (APP_BUNDLE_PREFIX in project.pbxproj, DEVELOPMENT_TEAM in build settings).
const APP_BUNDLE_PREFIX = 'com.zaytech';
const TEAM_ID = 'L9KEX9UZ27';
const PUBLIC_DOMAIN = process.env.PUBLIC_DOMAIN || 'chocolate-shark-236082.hostingersite.com';

// Fingerprint match window for the iOS fallback (no App Clip / no recovered
// code) — 48h, same as documented for the real backend's IP+language match.
const MATCH_WINDOW_HOURS = 48;

// slug -> bundle-id slug, synced from RestaurantApp/merchants.json. Only used to
// generate the apple-app-site-association file (which app+clip owns which /r/<slug>/*
// path) — nothing here is a secret.
const merchants = JSON.parse(fs.readFileSync(path.join(__dirname, 'merchants.json'), 'utf8'));

// slug -> settings.referral object, shaped exactly like the real
// GET /v2/group-merchants/{slug} bootstrap response's settings.referral block.
// _default covers any merchant not explicitly configured (test data only —
// the real backend is the source of truth once the app points at it).
const referralSettings = JSON.parse(fs.readFileSync(path.join(__dirname, 'referral-settings.json'), 'utf8'));
function settingsFor(slug) {
  return referralSettings[slug] || referralSettings._default;
}

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

// ── Code generation ───────────────────────────────────────────────────────────
// Unambiguous alphabet per the real backend's spec: no O/0, I/1, L — avoids
// characters that are easy to misread when a code is read aloud or handwritten.
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

  -- One row per GET /r/:slug/:code tap. Powers the iOS fingerprint fallback —
  -- the real backend's documented "hashed IP + platform + language" match.
  CREATE TABLE IF NOT EXISTS clicks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    code           TEXT NOT NULL,
    merchant_slug  TEXT NOT NULL,
    ip_hash        TEXT NOT NULL,
    platform       TEXT NOT NULL,
    accept_language TEXT,
    consumed       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_clicks_match ON clicks(merchant_slug, ip_hash, platform, accept_language, consumed);

  -- One row per successful claim (App-Clip-code path or fingerprint-match
  -- path). Backs already_referred / device_used / self_referral checks.
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
  INSERT INTO clicks (code, merchant_slug, ip_hash, platform, accept_language)
  VALUES (@code, @merchant_slug, @ip_hash, @platform, @accept_language)
`);
const recentClicks = db.prepare(`SELECT * FROM clicks ORDER BY id DESC LIMIT 50`);
const findFingerprintMatch = db.prepare(`
  SELECT * FROM clicks
  WHERE merchant_slug = @merchant_slug
    AND ip_hash = @ip_hash
    AND platform = @platform
    AND accept_language = @accept_language
    AND consumed = 0
    AND created_at > datetime('now', '-${MATCH_WINDOW_HOURS} hours')
  ORDER BY created_at DESC LIMIT 1
`);
const consumeClick = db.prepare(`UPDATE clicks SET consumed = 1 WHERE id = ?`);

const getClaimForCustomer = db.prepare(`SELECT * FROM claims WHERE merchant_slug = ? AND customer_token = ?`);
const findClaimByDevice = db.prepare(`SELECT * FROM claims WHERE merchant_slug = ? AND device_id = ? AND device_id IS NOT NULL AND device_id != ''`);
const insertClaim = db.prepare(`
  INSERT INTO claims (merchant_slug, customer_token, device_id, referral_code, matched_via)
  VALUES (@merchant_slug, @customer_token, @device_id, @referral_code, @matched_via)
`);
const recentClaims = db.prepare(`SELECT * FROM claims ORDER BY id DESC LIMIT 50`);

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

// apple-app-site-association — no extension, served over https, no redirect.
// Must stay under Apple's 128kb uncompressed limit (currently well under it —
// see console output at boot for the current size).
app.get('/.well-known/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});
app.get('/apple-app-site-association', (req, res) => {
  res.type('application/json').send(JSON.stringify(AASA));
});

// GET /r/:slug/:code — the actual tapped link. Logs a click (fingerprint
// fallback signal for iOS) and redirects to the store. The App Clip itself
// never hits this route — it's launched directly from the associated domain
// before any network request. This only fires for: Android (always, to pick
// up &referrer=), old iOS without App Clip support, or desktop browsers.
app.get('/r/:slug/:code', (req, res) => {
  const { slug, code } = req.params;
  if (!merchants[slug]) {
    return res.status(404).send('Unknown merchant.');
  }
  const platform = platformFromUserAgent(req.headers['user-agent']);
  insertClick.run({
    code,
    merchant_slug: slug,
    ip_hash: hashIp(normalizeIp(req.ip)),
    platform,
    accept_language: req.headers['accept-language'] || null,
  });

  if (platform === 'android') {
    // Real merchant Play Store URL goes here once the Android app exists.
    return res.redirect(`https://play.google.com/store/apps/details?id=${APP_BUNDLE_PREFIX}.${merchants[slug]}&referrer=${encodeURIComponent(code)}`);
  }
  // iOS: plain App Store URL, no code — the App Store strips any param anyway.
  // Real merchant App Store ID goes here once each merchant app is live.
  res.redirect(`https://apps.apple.com/app/${APP_BUNDLE_PREFIX}.${merchants[slug]}`);
});

// ── Real API contract (mirrors the production backend so app code doesn't
// change when it points at api-v2(-sandbox).smartonlineorders.com instead) ──

// GET /v2/group-merchants/:slug — subset of the real bootstrap response.
// No auth: this is read before the customer has a session.
app.get('/v2/group-merchants/:slug', (req, res) => {
  const { slug } = req.params;
  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_slug' });
  }
  res.json({ settings: { referral: settingsFor(slug) } });
});

// GET /v2/group-merchants/:slug/customers/referral — the referrer's link.
// Real auth is a group-scoped customer JWT; here any bearer token is a
// stand-in customer identity, scoped by (slug, token) like the real JWT is
// scoped by group.
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

// POST /v2/group-merchants/:slug/customers/referrals/claim — always 200 once
// authenticated, fire-and-forget from the app's perspective. Two paths:
//   - referral_code present (Android's Play Install Referrer, or iOS's App
//     Clip / Universal Link handoff) → exact match.
//   - referral_code absent (iOS with no App Clip recovery) → fingerprint
//     match against recent clicks: hashed IP + platform + Accept-Language,
//     within the match window.
app.post('/v2/group-merchants/:slug/customers/referrals/claim', (req, res) => {
  const { slug } = req.params;
  const token = bearerToken(req);
  const deviceId = req.headers['x-soo-device-id'] || '';
  const acceptLanguage = req.headers['accept-language'] || null;
  const { referral_code } = req.body || {};

  if (!merchants[slug]) {
    return res.status(404).json({ error: 'unknown_slug' });
  }
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const settings = settingsFor(slug);
    if (!settings.enabled) {
      return res.json({ attributed: false, reason: 'program_inactive' });
    }

    if (getClaimForCustomer.get(slug, token)) {
      return res.json({ attributed: false, reason: 'already_referred' });
    }

    if (deviceId && findClaimByDevice.get(slug, deviceId)) {
      return res.json({ attributed: false, reason: 'device_used' });
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

    // No code — iOS fingerprint fallback.
    const platform = platformFromUserAgent(req.headers['user-agent']);
    const match = findFingerprintMatch.get({
      merchant_slug: slug,
      ip_hash: hashIp(normalizeIp(req.ip)),
      platform,
      accept_language: acceptLanguage,
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
  });
});

app.post('/debug/reset', (req, res) => {
  db.exec('DELETE FROM referral_codes; DELETE FROM clicks; DELETE FROM claims;');
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4001;
app.listen(PORT, '0.0.0.0', () => {
  const aasaSize = Buffer.byteLength(JSON.stringify(AASA));
  console.log(`\n🔗 Referral server running (mirrors /v2/group-merchants/{slug}/... contract)`);
  console.log(`   Dashboard:        http://localhost:${PORT}`);
  console.log(`   Public domain:    https://${PUBLIC_DOMAIN}`);
  console.log(`   Merchants loaded: ${Object.keys(merchants).length} (AASA size: ${aasaSize} bytes / 128000 max)`);
  console.log(`   Settings:         GET  http://localhost:${PORT}/v2/group-merchants/:slug`);
  console.log(`   Referral link:    GET  http://localhost:${PORT}/v2/group-merchants/:slug/customers/referral`);
  console.log(`   Claim:            POST http://localhost:${PORT}/v2/group-merchants/:slug/customers/referrals/claim\n`);
});
