/**
 * server.js — Covenant Crest Group Ltd Backend API  v2.0
 * =======================================================
 * Express + JSON file-store backend deployed on Render.com
 *
 * NEW IN v2.0:
 *   ✅ bcrypt password hashing (no more plain-text passwords)
 *   ✅ Transactional email via Resend (form alerts + welcome emails)
 *   ✅ Cloudinary image upload for job listings (logo / photo)
 *   ✅ Netlify webhook signature verification (security)
 *   ✅ Rate limiting on auth routes (brute-force protection)
 *   ✅ Input sanitisation on all public routes
 *   ✅ Candidate CV upload via Cloudinary
 *   ✅ Applications endpoint (from recruitment.html)
 *   ✅ Clean /api/health + uptime probe
 *
 * DEPLOY TO RENDER.COM
 * ─────────────────────
 * 1. Push this repo to GitHub
 * 2. Render → New Web Service → connect repo
 * 3. Build command : npm install
 * 4. Start command : node server.js
 * 5. Set all environment variables below in Render → Environment
 *
 * ENVIRONMENT VARIABLES  (set in Render dashboard — never commit these)
 * ─────────────────────────────────────────────────────────────────────
 *  SUPER_ADMIN_EMAIL        your admin email  (e.g. jaby.k@covenantcrest.co.uk)
 *  SUPER_ADMIN_PWD          strong password (min 8 chars)
 *  JWT_SECRET               long random string (use: openssl rand -hex 32)
 *  ALLOWED_ORIGIN           https://covenantcrest.co.uk
 *
 *  RESEND_API_KEY           re_xxxxxxxxxxxxxxxxxxxxxxxx  (resend.com — free tier)
 *  EMAIL_FROM               noreply@covenantcrest.co.uk  (must be verified domain in Resend)
 *  EMAIL_NOTIFY             jaby.k@covenantcrest.co.uk   (where you receive alerts)
 *
 *  CLOUDINARY_CLOUD_NAME    your cloud name from cloudinary.com dashboard
 *  CLOUDINARY_API_KEY       your api key
 *  CLOUDINARY_API_SECRET    your api secret
 *
 *  NETLIFY_WEBHOOK_SECRET   set same value in Netlify → Forms → Webhook → Secret
 *                           (optional but recommended)
 * =======================================================
 */

'use strict';

require('dotenv').config();

// ─────────────────────────────────────────────
// PLATFORM COMPATIBILITY
// Works on: Render.com, Railway.app, Heroku, Fly.io, VPS, local
// Railway:  set env vars in Railway dashboard → Variables tab
//           Railway auto-sets PORT — don't override it
//           Deploy: connect GitHub repo → Railway auto-deploys on push
// ─────────────────────────────────────────────

const express  = require('express');
const cors     = require('cors');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const https    = require('https');
const helmet   = require('helmet');
const bcrypt   = require('bcrypt');
const mongoose = require('mongoose');

const app  = express();
const PORT = process.env.PORT || 3001;

// Load persisted admin password if changed via admin panel
(function loadPersistedPassword() {
  try {
    const pwFile = require('path').join(
      process.env.DATA_DIR || require('path').join(__dirname, 'data'),
      '.admin_pw'
    );
    if (require('fs').existsSync(pwFile)) {
      const saved = require('fs').readFileSync(pwFile, 'utf8').trim();
      if (saved) {
        // Will be applied after CFG is defined below
        process.env._SAVED_ADMIN_PW = saved;
      }
    }
  } catch(e) { /* non-fatal */ }
})();

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────
const CFG = {
  SUPER_ADMIN_EMAIL : process.env.SUPER_ADMIN_EMAIL || 'jaby.k@covenantcrest.co.uk',
  SUPER_ADMIN_PWD   : process.env._SAVED_ADMIN_PW || process.env.SUPER_ADMIN_PWD || (() => { console.error('\n⚠️  CRITICAL: SUPER_ADMIN_PWD env var is not set. Using insecure default. Set SUPER_ADMIN_PWD in Render → Environment immediately.\n'); return 'ChangeMe2025!'; })(),
  JWT_SECRET        : process.env.JWT_SECRET        || (() => { console.error('\n⚠️  CRITICAL: JWT_SECRET env var is not set. Sessions will be invalidated on every restart. Set JWT_SECRET in Render → Environment.\n'); return crypto.randomBytes(32).toString('hex'); })(),
  ALLOWED_ORIGIN    : process.env.ALLOWED_ORIGIN    || 'https://covenantcrest.co.uk',
  SUPER_ADMIN_2FA_SECRET: process.env.SUPER_ADMIN_2FA_SECRET || '',

  // Email (Resend)
  RESEND_API_KEY    : process.env.RESEND_API_KEY    || '',
  EMAIL_FROM        : process.env.EMAIL_FROM        || 'noreply@covenantcrest.co.uk',
  EMAIL_NOTIFY      : process.env.EMAIL_NOTIFY      || 'recruitment@covenantcrest.co.uk',

  // Cloudinary (will also check CLOUDINARY_URL below)
  CLOUDINARY_CLOUD  : (process.env.CLOUDINARY_CLOUD_NAME || '').trim(),
  CLOUDINARY_KEY    : (process.env.CLOUDINARY_API_KEY    || '').trim(),
  CLOUDINARY_SECRET : (process.env.CLOUDINARY_API_SECRET || '').trim(),

  // Netlify webhook secret (optional)
  NETLIFY_SECRET    : process.env.NETLIFY_WEBHOOK_SECRET || '',

  // HubSpot CRM (https://app.hubspot.com -> Private App Access Token)
  HUBSPOT_ACCESS_TOKEN: process.env.HUBSPOT_ACCESS_TOKEN || '',

  // Microsoft SSO (Azure AD OAuth 2.0)
  MICROSOFT_CLIENT_ID    : process.env.MICROSOFT_CLIENT_ID || '',
  MICROSOFT_CLIENT_SECRET: process.env.MICROSOFT_CLIENT_SECRET || '',
  MICROSOFT_REDIRECT_URI : process.env.MICROSOFT_REDIRECT_URI || 'https://www.covenantcrest.co.uk/api/auth/microsoft-callback',
  MICROSOFT_TENANT_ID    : process.env.MICROSOFT_TENANT_ID || 'common',

  // Database
  MONGODB_URI        : process.env.MONGODB_URI        || '',
};

// Extract from CLOUDINARY_URL if provided (cloudinary://key:secret@cloud)
if (process.env.CLOUDINARY_URL) {
  const match = process.env.CLOUDINARY_URL.match(/cloudinary:\/\/([^:]+):([^@]+)@(.+)/);
  if (match) {
    CFG.CLOUDINARY_KEY    = match[1].trim();
    CFG.CLOUDINARY_SECRET = match[2].trim();
    CFG.CLOUDINARY_CLOUD  = match[3].trim();
  }
}

// ─────────────────────────────────────────────
// DATA DIRECTORY & FILE PATHS
// ─────────────────────────────────────────────
const DATA_DIR  = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const FILES = {
  jobs    : path.join(DATA_DIR, 'jobs.json'),
  contacts: path.join(DATA_DIR, 'contacts.json'),
  users   : path.join(DATA_DIR, 'users.json'),
  apps    : path.join(DATA_DIR, 'applications.json'),
  security: path.join(DATA_DIR, 'security.json'),
};

// ─────────────────────────────────────────────
// DATABASE CONNECTION
// ─────────────────────────────────────────────
if (CFG.MONGODB_URI) {
  mongoose.connect(CFG.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));
} else {
  console.warn('⚠ No MONGODB_URI provided. Data will NOT be persistent after server restarts!');
}

// Define Schemas
const JobSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  title: String,
  pay: String,
  sector: String,
  type: String,
  location: String,
  status: { type: String, default: 'active' },
  desc: String,
  req: String,
  imageUrl: String,
  closingDate: String,
  seoKeywords: String,
  seoDesc: String,
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const ContactSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  email: String,
  phone: String,
  company: String, // Bug 7: Structured B2B company field
  type: String,
  message: String,
  source: String,
  notes: String,
  adminNotes: String,
  status: { type: String, default: 'new' },
  read: { type: Boolean, default: false },
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const AppSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  first_name: String,
  last_name: String,
  email: String,
  phone: String,
  job_id: String,
  job_title: String,
  sector: String,
  availability: String,
  notes: String,
  adminNotes: String,
  cvUrl: String,
  cvBase64: String, // though we prefer Cloudinary
  status: { type: String, default: 'new' },
  matchScore: Number,
  rejectionReason: String,
  requestedDocs: String,
  // Compliance fields
  dbs_level: String,
  dbs_issue_date: String,
  dbs_expiry_date: String,
  dbs_cert_number: String,
  sia_licence_number: String,
  sia_expiry_date: String,
  rtw_doc_type: String,
  rtw_expiry_date: String,
  rtw_verified: { type: Boolean, default: false },
  manual_handling_cert: String,
  compliance_notes: String,
  compliance_status: { type: String, default: 'incomplete' },
  source: String,
  rating: Number,
  // Extracted and mapped from frontend forms
  postcode: String,
  rtw_status: String,
  visa_details: String,
  is_veteran: String,
  assistance: String,
  nmc_pin: String,
  cscs_number: String,
  food_hygiene_level: String,
  hgv_license: String,
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const UserSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'employee' },
  created: { type: Date, default: Date.now }
}, { timestamps: true });

const SecurityLogSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  timestamp: { type: Date, default: Date.now },
  type: String,
  email: String,
  ip: String,
  userAgent: String,
  role: String,
  exists: Boolean,
}, { timestamps: true });

const Job = mongoose.models.Job || mongoose.model('Job', JobSchema);
const Contact = mongoose.models.Contact || mongoose.model('Contact', ContactSchema);
const Application = mongoose.models.Application || mongoose.model('Application', AppSchema);
const User = mongoose.models.User || mongoose.model('User', UserSchema);
const SecurityLog = mongoose.models.SecurityLog || mongoose.model('SecurityLog', SecurityLogSchema);

// ── Job Alert Schema ─────────────────────────────────────────────────────────
const JobAlertSchema = new mongoose.Schema({
  id           : { type: String, unique: true },
  email        : { type: String, required: true, lowercase: true, trim: true },
  sectors      : [{ type: String }],           // [] = all sectors
  token        : { type: String, unique: true },// unsubscribe token
  confirmed    : { type: Boolean, default: true },
  createdAt    : { type: Date, default: Date.now },
});
const JobAlert = mongoose.models.JobAlert || mongoose.model('JobAlert', JobAlertSchema);

// ─────────────────────────────────────────────
// JSON FILE HELPERS (Kept for fallback/migration)
// ─────────────────────────────────────────────
function readJSON(filePath, def = []) {
  try {
    if (!fs.existsSync(filePath)) return def;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    console.error('readJSON error:', filePath, e.message);
    return def;
  }
}

function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('writeJSON error:', filePath, e.message);
    return false;
  }
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function sanitise(str, max = 500) {
  // Netlify webhooks can send repeated fields as arrays — take first element
  if (Array.isArray(str)) str = str[0];
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, max);
}

// ── Cookie helpers ────────────────────────────────────────────────
// Parse Cookie header into key/value object (no external library needed)
function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, pair) => {
    const idx = pair.indexOf('=');
    if (idx < 1) return acc;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    try { acc[key] = decodeURIComponent(val); } catch { acc[key] = val; }
    return acc;
  }, {});
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', [
    `cc_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}; SameSite=Strict${process.env.RENDER ? '; Secure' : ''}`
  ]);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', [
    'cc_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict'
  ]);
}

// ── One-time SSO code store (replaces JWT-in-URL-fragment) ────────
// Code is valid for 90 seconds — enough for the page load and exchange
const ssoCodeStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of ssoCodeStore) {
    if (data.expires < now) ssoCodeStore.delete(code);
  }
}, 30000).unref();

// Escape HTML special chars before inserting user-supplied text into email HTML
function htmlEsc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Log security events (failed logins, password changes) — stored in MongoDB
 */
function logSecurityEvent(type, email, req, details = {}) {
  try {
    const entry = new SecurityLog({
      id:        uid(),
      timestamp: new Date(),
      type,
      email:     email.toLowerCase(),
      ip:        req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'],
      ...details
    });
    entry.save().catch(e => console.error('Security log save failed:', e.message));
    // Prune to keep only the last 200 events (non-blocking)
    SecurityLog.countDocuments().then(count => {
      if (count > 200) {
        SecurityLog.find().sort({ timestamp: 1 }).limit(count - 200)
          .then(old => SecurityLog.deleteMany({ _id: { $in: old.map(o => o._id) } }))
          .catch(() => {});
      }
    }).catch(() => {});
  } catch (e) { console.error('Security log failed:', e.message); }
}

// ─────────────────────────────────────────────
// PASSWORD HASHING (bcrypt)
// ─────────────────────────────────────────────
async function hashPassword(pwd) {
  return bcrypt.hash(pwd, 12);
}

async function verifyPassword(pwd, stored) {
  if (!stored) return false;
  // Fallback for legacy plain-text passwords — use timing-safe comparison
  if (!stored.startsWith('$2') && !stored.startsWith('pbkdf2$')) {
    try {
      const a = Buffer.from(pwd);
      const b = Buffer.from(stored);
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    } catch { return false; }
  }
  // Fallback for previous PBKDF2 implementation
  if (stored.startsWith('pbkdf2$')) {
    return new Promise((resolve, reject) => {
      try {
        const parts = stored.split('$');
        const salt = parts[1];
        const hash = parts[2];
        crypto.pbkdf2(pwd, salt, 100000, 64, 'sha512', (err, key) => {
          if (err) return reject(err);
          resolve(key.toString('hex') === hash);
        });
      } catch (e) { resolve(false); }
    });
  }
  return bcrypt.compare(pwd, stored);
}

// ─────────────────────────────────────────────
// SIMPLE JWT  (no external library)
// ─────────────────────────────────────────────
function b64u(data) {
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

function makeToken(payload, expiresInSeconds = 86400 * 7) {
  const header = b64u({ alg: 'HS256', typ: 'JWT' });
  const body   = b64u({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + expiresInSeconds });
  const sig    = crypto.createHmac('sha256', CFG.JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', CFG.JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// Native TOTP verification helper (Microsoft/Google Authenticator compatible)
function verifyTOTP(token, secret) {
  if (!token || !secret) return false;
  token = String(token).replace(/\s+/g, '');
  if (!/^\d{6}$/.test(token)) return false;

  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  const cleanSecret = secret.toUpperCase().replace(/\s+/g, '');
  for (let i = 0; i < cleanSecret.length; i++) {
    const val = base32chars.indexOf(cleanSecret.charAt(i));
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  
  const keyBytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    keyBytes.push(parseInt(bits.substr(i, 8), 2));
  }
  const key = Buffer.from(keyBytes);

  const timeStep = 30;
  const currentStep = Math.floor(Date.now() / 1000 / timeStep);

  for (let stepOffset = -1; stepOffset <= 1; stepOffset++) {
    const step = currentStep + stepOffset;
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(step / 0x100000000), 0);
    buf.writeUInt32BE(step % 0x100000000, 4);

    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);

    const checkToken = String(code % 1000000).padStart(6, '0');
    if (checkToken === token) return true;
  }
  return false;
}


// ── Email templates ─────────────────────────
const emailTpl = {
  /* Admin alert when a new enquiry arrives */
  newEnquiryAlert({ name, email, phone, type, message, source }) {
    return {
      to     : CFG.EMAIL_NOTIFY,
      subject: `[Covenant Crest] New ${type || 'general'} enquiry from ${name}`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">New Enquiry — Covenant Crest</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px 0;color:#666;font-size:13px;width:120px;">Name</td><td style="padding:8px 0;font-weight:600;font-size:13px;">${htmlEsc(name)}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Email</td><td style="padding:8px 0;font-size:13px;"><a href="mailto:${htmlEsc(email)}" style="color:#C9A84C;">${htmlEsc(email)}</a></td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Phone</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(phone) || 'Not provided'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Type</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(type) || 'General'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Source</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(source) || 'website'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;vertical-align:top;">Message</td><td style="padding:8px 0;font-size:13px;line-height:1.6;">${htmlEsc(message || '').replace(/\n/g, '<br>')}</td></tr>
            </table>
            <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:11px;color:#999;margin:0;">Received: ${new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' })} · Source: ${source}</p>
          </div>
        </div>`,
    };
  },

  /* Auto-reply to the enquirer */
  enquiryAutoReply({ name, type }) {
    const typeLabel = {
      haulage  : 'haulage & freight',
      trade    : 'import & trade',
      general  : 'general',
      contact  : 'general',
    }[type] || 'general';
    return {
      to     : null,  // set dynamically
      subject: `Thank you for your enquiry — Covenant Crest Group`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">Thank You, ${htmlEsc(name)}</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <p style="font-size:14px;line-height:1.7;color:#333;">We have received your <strong>${typeLabel}</strong> enquiry and a member of our team will be in touch shortly.</p>
            <p style="font-size:14px;line-height:1.7;color:#333;">If your matter is urgent, please call us directly on <a href="tel:07346809846" style="color:#C9A84C;font-weight:600;">07346 809846</a>.</p>
            <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:12px;color:#888;">Covenant Crest Group Ltd · Company No. 16528951 · Telford, Shropshire</p>
          </div>
        </div>`,
    };
  },

  /* Auto-reply to candidate confirming application received */
  applicationAutoReply({ first_name, last_name, sector, job_title }) {
    const sectorLabel = { care:'care & healthcare', security:'security', warehouse:'warehouse & logistics' }[sector] || sector || 'your chosen';
    return {
      to     : null,  // set dynamically
      subject: `We received your application — Covenant Crest Group`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">Application Received</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <p style="font-size:14px;line-height:1.7;color:#333;">Dear <strong>${htmlEsc(first_name)} ${htmlEsc(last_name)}</strong>,</p>
            <p style="font-size:14px;line-height:1.7;color:#333;">Thank you for applying for a <strong>${htmlEsc(sectorLabel)}</strong> role${job_title ? ' (<em>' + htmlEsc(job_title) + '</em>)' : ''} with Covenant Crest Group Ltd.</p>
            <p style="font-size:14px;line-height:1.7;color:#333;">We have received your application and our recruitment team will review it shortly. If your profile matches our current requirements, a consultant will be in touch within <strong>24–48 hours</strong>.</p>
            <div style="background:#f0f7f0;border-left:3px solid #C9A84C;padding:14px 18px;margin:20px 0;border-radius:0 6px 6px 0;">
              <p style="font-size:13px;color:#333;margin:0;">If your matter is urgent, please call us directly on <a href="tel:07346809846" style="color:#C9A84C;font-weight:600;">07346 809846</a> or email <a href="mailto:recruitment@covenantcrest.co.uk" style="color:#C9A84C;">recruitment@covenantcrest.co.uk</a>.</p>
            </div>
            <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:12px;color:#888;margin:0;">Covenant Crest Group Ltd &middot; Company No. 16528951 &middot; Telford, Shropshire</p>
            <p style="font-size:11px;color:#bbb;margin:4px 0 0;">This is an automated confirmation. Please do not reply to this email.</p>
          </div>
        </div>`,
    };
  },

  /* Admin alert when a candidate applies */
  newApplicationAlert({ first_name, last_name, email, phone, sector, job_title, cvUrl }, cvBase64, cvFileName) {
    const emailData = {
      to     : CFG.EMAIL_NOTIFY,
      subject: `[Covenant Crest] New application — ${first_name} ${last_name} (${sector || 'general'})`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">New Candidate Application</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px 0;color:#666;font-size:13px;width:120px;">Name</td><td style="padding:8px 0;font-weight:600;font-size:13px;">${htmlEsc(first_name)} ${htmlEsc(last_name)}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Email</td><td style="padding:8px 0;font-size:13px;"><a href="mailto:${htmlEsc(email)}" style="color:#C9A84C;">${htmlEsc(email)}</a></td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Phone</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(phone) || 'Not provided'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Sector</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(sector) || '—'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Job</td><td style="padding:8px 0;font-size:13px;">${htmlEsc(job_title) || '—'}</td></tr>
              ${cvUrl ? `<tr><td style="padding:8px 0;color:#666;font-size:13px;">Cloud Link</td><td style="padding:8px 0;font-size:13px;"><a href="${cvUrl}" target="_blank" style="color:#C9A84C;">View Online CV</a></td></tr>` : ''}
            </table>
            <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:11px;color:#999;margin:0;">Received: ${new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' })}</p>
          </div>
        </div>`,
    };
    if (cvBase64 && cvFileName) {
      emailData.attachments = [{
        content: cvBase64,
        filename: cvFileName
      }];
    }
    return emailData;
  },

  /* Job alert email — sent to subscriber when a matching new job is posted */
  jobAlertEmail({ email, job, unsubscribeUrl }) {
    return {
      to     : email,
      subject: `New Job Alert: ${htmlEsc(job.title)} — Covenant Crest`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">New Job — Just Posted</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <p style="font-size:14px;color:#333;margin:0 0 6px;">A new job matching your alert has been posted:</p>
            <div style="background:#f9f6f0;border-left:3px solid #C9A84C;border-radius:0 6px 6px 0;padding:16px 18px;margin:16px 0;">
              <p style="font-size:18px;font-weight:700;color:#0D1B2A;margin:0 0 6px;">${htmlEsc(job.title)}</p>
              <p style="font-size:13px;color:#666;margin:0;">📍 ${htmlEsc(job.location || 'UK')} &nbsp;|&nbsp; 💷 ${htmlEsc(job.pay || 'Competitive')} &nbsp;|&nbsp; ${htmlEsc(job.type || 'Full-time')}</p>
            </div>
            <a href="https://www.covenantcrest.co.uk/job?id=${job.id}" style="display:inline-block;background:#C9A84C;color:#0D1B2A;font-family:Arial,sans-serif;font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:12px 28px;border-radius:4px;text-decoration:none;margin:8px 0 20px;">View &amp; Apply →</a>
            <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:11px;color:#999;margin:0;">You're receiving this because you set up a job alert at covenantcrest.co.uk.<br>
            <a href="${unsubscribeUrl}" style="color:#C9A84C;">Unsubscribe from job alerts</a></p>
          </div>
        </div>`,
    };
    if (cvBase64 && cvFileName) {
      emailData.attachments = [{
        content: cvBase64,
        filename: cvFileName
      }];
    }
    return emailData;
  },
};

// ─────────────────────────────────────────────
// CLOUDINARY UPLOAD HELPER
// Uses Cloudinary's unsigned preset via HTTPS (no SDK needed)
// Accepts base64 data from client or a file buffer
// ─────────────────────────────────────────────
function cloudinaryUpload(base64Data, folder = 'covenantcrest', publicId = null, resourceType = 'auto') {
  if (!CFG.CLOUDINARY_CLOUD || !CFG.CLOUDINARY_KEY || !CFG.CLOUDINARY_SECRET) {
    return Promise.reject(new Error('Cloudinary credentials not configured.'));
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const params    = { timestamp, folder };
  if (publicId) params.public_id = publicId;

  // Build signature
  const sigStr = Object.keys(params).sort()
    .map(k => `${k}=${params[k]}`).join('&') + CFG.CLOUDINARY_SECRET;
  const signature = crypto.createHash('sha1').update(sigStr).digest('hex');

  // Detect file type from base64 header for proper upload path
  const fileHeader = base64Data.substring(0, 30);
  let uploadPath = 'image/upload';
  if (resourceType === 'auto' || resourceType === 'raw') {
    // PDFs and docs go to raw upload
    if (fileHeader.includes('JVBER') || fileHeader.includes('JVBERi')) {
      uploadPath = 'raw/upload'; // PDF
    } else if (fileHeader.includes('UEsDB') || fileHeader.includes('UEsDBA')) {
      uploadPath = 'raw/upload'; // Word doc (zip-based)
    } else {
      uploadPath = 'image/upload'; // images
    }
  }

  // Build multipart body manually (minimal implementation)
  const boundary = '----CCBoundary' + Date.now();
  const parts = [];

  function addField(name, value) {
    parts.push(
      `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}`
    );
  }

  addField('file',      `data:application/octet-stream;base64,${base64Data}`);
  addField('api_key',   CFG.CLOUDINARY_KEY);
  addField('timestamp', timestamp);
  addField('folder',    folder);
  addField('signature', signature);
  if (publicId) addField('public_id', publicId);

  const bodyStr = parts.join('\r\n') + `\r\n--${boundary}--\r\n`;
  const bodyBuf = Buffer.from(bodyStr, 'utf8');

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.cloudinary.com',
      path    : `/v1_1/${CFG.CLOUDINARY_CLOUD}/${uploadPath}`,
      method  : 'POST',
      headers : {
        'Content-Type'  : `multipart/form-data; boundary=${boundary}`,
        'Content-Length': bodyBuf.length,
      },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode >= 400) return reject(new Error(json.error?.message || 'Cloudinary error'));
          resolve({ url: json.secure_url, publicId: json.public_id });
        } catch { reject(new Error('Cloudinary response parse error')); }
      });
    });
    req.on('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

// ─────────────────────────────────────────────
// SIMPLE RATE LIMITER (in-memory, resets on restart)
// ─────────────────────────────────────────────
const rateLimitStore = new Map();

// Purge expired entries every 10 minutes to prevent unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 10 * 60 * 1000).unref();

function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key = req.ip + ':' + req.path;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > entry.resetAt) {
      entry.count   = 0;
      entry.resetAt = now + windowMs;
    }
    entry.count++;
    rateLimitStore.set(key, entry);

    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many attempts. Please wait a moment.' });
    }
    next();
  };
}

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.set('trust proxy', 1);

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false, // Netlify handles CSP for the frontend
}));

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    const base = (CFG.ALLOWED_ORIGIN || '').replace(/^https?:\/\//, '');
    const allowed = [
      CFG.ALLOWED_ORIGIN,
      'https://www.' + base,
      'http://www.'  + base,
    ];
    // Allow localhost only when running locally (not on Render)
    if (!process.env.RENDER) {
      allowed.push('http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500');
    }
    if (allowed.includes(origin)) return cb(null, true);
    cb(null, false);
  },
  credentials: true,
}));

app.use(express.json({
  limit: '5mb',
  verify: (req, _res, buf) => { req.rawBody = buf; },
}));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  // Prefer httpOnly cookie; fall back to Authorization header for dev/backwards compat
  const cookies = parseCookies(req);
  const cookieToken = cookies.cc_session ? decodeURIComponent(cookies.cc_session) : null;
  const bearerToken = (req.headers['authorization'] || '').startsWith('Bearer ')
    ? req.headers['authorization'].slice(7) : null;
  const user = verifyToken(cookieToken) || verifyToken(bearerToken);
  if (!user) return res.status(401).json({ error: 'Unauthorised. Please log in.' });
  req.user = user;
  next();
}

function requireSuperAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Forbidden. Super Admin access required.' });
    }
    next();
  });
}

// ─────────────────────────────────────────────
// CLOUDINARY DELETE HELPER
// ─────────────────────────────────────────────
function cloudinaryDelete(imageUrl) {
  if (!imageUrl || !CFG.CLOUDINARY_CLOUD || !CFG.CLOUDINARY_KEY || !CFG.CLOUDINARY_SECRET) return Promise.resolve();
  // Extract public_id from URL: strip version, leading slash, and extension
  // e.g. https://res.cloudinary.com/cloud/image/upload/v123/folder/name.jpg → folder/name
  const match = imageUrl.match(/\/upload\/(?:v\d+\/)?(.+?)(\.[^.]+)?$/);
  if (!match) return Promise.resolve();
  const publicId = match[1];
  const resourceType = imageUrl.includes('/raw/') ? 'raw' : 'image';

  const timestamp = Math.floor(Date.now() / 1000);
  const sigStr    = `public_id=${publicId}&timestamp=${timestamp}` + CFG.CLOUDINARY_SECRET;
  const signature = crypto.createHash('sha1').update(sigStr).digest('hex');

  const body = new URLSearchParams({ public_id: publicId, api_key: CFG.CLOUDINARY_KEY, timestamp, signature }).toString();
  const bodyBuf = Buffer.from(body);

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.cloudinary.com',
      path    : `/v1_1/${CFG.CLOUDINARY_CLOUD}/${resourceType}/destroy`,
      method  : 'POST',
      headers : { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': bodyBuf.length },
    }, (res) => {
      res.resume();
      resolve();
    });
    req.on('error', () => resolve());
    req.write(bodyBuf);
    req.end();
  });
}

// ─────────────────────────────────────────────
// SEED DEFAULT JOBS
// ─────────────────────────────────────────────
async function seedDefaultJobs() {
  try {
    const count = await Job.countDocuments();
    if (count > 0) return;
    const defaults = [
      { id: uid(), title: 'Care Assistant',       sector: 'care',      type: 'full-time',  location: 'Telford',       pay: '£11.44–12.50/hr', desc: 'Compassionate care assistant needed in Telford to support elderly residents with daily living, personal care and companionship.', req: 'Enhanced DBS required. Experience preferred but not essential. Full training provided.', status: 'active' },
      { id: uid(), title: 'Night Care Worker',     sector: 'care',      type: 'full-time',  location: 'Telford',       pay: '£12.00–13.50/hr', desc: 'Night shift care worker for a residential care home in Telford. Overnight personal care, medication and safety monitoring.',         req: 'Enhanced DBS. Night working experience preferred.',                                   status: 'active' },
      { id: uid(), title: 'SIA Door Supervisor',   sector: 'security',  type: 'full-time',  location: 'Birmingham',    pay: '£13.00–15.00/hr', desc: 'Licensed Door Supervisor for various Birmingham city centre venues. Day and night shifts available.',                               req: 'Valid SIA Door Supervisor licence mandatory. Minimum 1 year experience.',              status: 'active' },
      { id: uid(), title: 'Retail Security Officer',sector: 'security', type: 'part-time',  location: 'Wolverhampton', pay: '£11.44–12.50/hr', desc: 'Retail security officer for a busy retail park in Wolverhampton. Loss prevention and customer service.',                           req: 'SIA licence preferred.',                                                              status: 'active' },
      { id: uid(), title: 'Warehouse Operative',   sector: 'warehouse', type: 'temporary',  location: 'Telford',       pay: '£11.44/hr',       desc: 'Warehouse operatives required immediately for a busy distribution centre. Picking, packing, goods-in and despatch.',              req: 'No experience necessary. Steel-toed boots required.',                                 status: 'active' },
      { id: uid(), title: 'FLT Driver',            sector: 'warehouse', type: 'permanent',  location: 'Shrewsbury',    pay: '£13.00–14.50/hr', desc: 'Experienced forklift truck driver required for a manufacturing site in Shrewsbury.',                                               req: 'Valid FLT licence (counter-balance essential). 2+ years experience.',                 status: 'active' },
    ];
    await Job.insertMany(defaults);
    console.log('✅ Seeded', defaults.length, 'default jobs to MongoDB');
  } catch(e) { console.error('Seeding failed:', e.message); }
}
if (CFG.MONGODB_URI) {
  seedDefaultJobs();
}
console.log('[BOOT] Cloudinary — cloud:', CFG.CLOUDINARY_CLOUD, '| key length:', CFG.CLOUDINARY_KEY.length, '| secret configured:', CFG.CLOUDINARY_SECRET.length > 0);

// ─────────────────────────────────────────────
// ROUTES — HEALTH
// ─────────────────────────────────────────────
app.get('/', (req, res) => res.json({
  status   : 'ok',
  service  : 'Covenant Crest API',
  version  : '2.0.0',
  timestamp: new Date().toISOString(),
}));

function healthPayload() {
  return {
    status: 'healthy',
    uptime: Math.floor(process.uptime()),
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    databaseConnected:       mongoose.connection.readyState === 1,
    hubspotConfigured:       !!CFG.HUBSPOT_ACCESS_TOKEN,
    resendConfigured:        !!CFG.RESEND_API_KEY,
    microsoftSSOConfigured:  !!(CFG.MICROSOFT_CLIENT_ID && CFG.MICROSOFT_CLIENT_SECRET),
  };
}
app.get('/health',     (req, res) => res.json(healthPayload()));
app.get('/api/health', (req, res) => res.json(healthPayload()));

// ─────────────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────────────

/**
 * POST /api/auth/login
 * Body: { email, password }
 * Returns: { token, role, email }
 */
app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
  const { email = '', password = '', honeypot = '', otp = '' } = req.body;
  const emailLc = email.trim().toLowerCase();

  // Honeypot check for bots
  if (honeypot) {
    console.warn('[security] Honeypot triggered by IP:', req.ip);
    return res.status(401).json({ error: 'Invalid request.' });
  }

  if (!emailLc || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    // ── Super Admin ──────────────────────────────────────────────
    if (emailLc === CFG.SUPER_ADMIN_EMAIL.toLowerCase()) {
      let match = false;
      try {
        match = await verifyPassword(password, CFG.SUPER_ADMIN_PWD);
      } catch (e) {
        match = (password === CFG.SUPER_ADMIN_PWD);
      }
      if (match) {
        // Enforce 2FA verification step if secret is configured on Render
        if (CFG.SUPER_ADMIN_2FA_SECRET) {
          if (!otp) {
            return res.status(202).json({ twoFactorRequired: true, message: '2FA verification code required.' });
          }
          const verified = verifyTOTP(otp, CFG.SUPER_ADMIN_2FA_SECRET);
          if (!verified) {
            logSecurityEvent('failed_2fa', emailLc, req, { role: 'superadmin' });
            return res.status(401).json({ error: 'Invalid 2FA authentication code.' });
          }
        }

        const token = makeToken({ email: emailLc, role: 'superadmin' });
        setSessionCookie(res, token);
        return res.json({ role: 'superadmin', email: emailLc });
      }
      // Log failed attempt
      logSecurityEvent('failed_login', emailLc, req, { role: 'superadmin' });
      await new Promise(r => setTimeout(r, 400 + Math.random() * 200));
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // ── Employee accounts (MongoDB) ───────────────────────────────
    const user = await User.findOne({ email: emailLc });
    if (user && user.role === 'employee') {
      let match = false;
      try {
        match = await verifyPassword(password, user.password);
      } catch (e) {
        match = (password === user.password);
      }
      if (match) {
        const token = makeToken({ email: user.email, role: 'employee', id: user.id });
        setSessionCookie(res, token);
        return res.json({ role: 'employee', email: user.email });
      }
    }

    // Log failed attempt
    logSecurityEvent('failed_login', emailLc, req, { exists: !!user });
    await new Promise(r => setTimeout(r, 400 + Math.random() * 200));
    return res.status(401).json({ error: 'Invalid email or password.' });

  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

/**
 * POST /api/auth/change-password — super admin only
 * Body: { currentPassword, newPassword }
 */
app.post('/api/auth/change-password', requireSuperAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

  // Verify current password
  let match = false;
  try {
    match = await verifyPassword(currentPassword, CFG.SUPER_ADMIN_PWD);
  } catch(e) {
    match = (currentPassword === CFG.SUPER_ADMIN_PWD);
  }

  if (!match) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  // Hash the new password and store in CFG (persists until next restart)
  try {
    const hashed = await hashPassword(newPassword);
    CFG.SUPER_ADMIN_PWD = hashed;
    // Also write to a local file so it survives restarts on Render
    const pwFile = path.join(DATA_DIR, '.admin_pw');
    fs.writeFileSync(pwFile, hashed, 'utf8');
    logSecurityEvent('password_change', CFG.SUPER_ADMIN_EMAIL, req);
    console.log('[auth] Super admin password changed successfully');
    return res.json({ success: true, message: 'Password changed successfully. Update SUPER_ADMIN_PWD in Render to make it permanent.' });
  } catch(e) {
    return res.status(500).json({ error: 'Failed to update password.' });
  }
});

/**
 * GET /api/auth/me
 */
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email, role: req.user.role });
});

/**
 * POST /api/auth/exchange-sso-code
 * Body: { code }
 * Exchanges the one-time SSO code for an httpOnly session cookie.
 * Code expires after 90 seconds and is deleted on first use.
 */
app.post('/api/auth/exchange-sso-code', (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Code is required.' });

  const data = ssoCodeStore.get(code);
  if (!data || data.expires < Date.now()) {
    ssoCodeStore.delete(code);
    return res.status(401).json({ error: 'Invalid or expired SSO code. Please sign in again.' });
  }

  // Single use — delete immediately after reading
  ssoCodeStore.delete(code);

  setSessionCookie(res, data.token);
  res.json({ role: data.role, email: data.email });
});

/**
 * POST /api/auth/logout
 * Clears the session cookie.
 */
app.post('/api/auth/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ success: true });
});

/**
 * GET /api/security-logs — Super Admin only
 */
app.get('/api/security-logs', requireSuperAdmin, async (req, res) => {
  try {
    const logs = await SecurityLog.find().sort({ timestamp: -1 }).limit(200);
    res.json(logs);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch security logs' }); }
});

// ─────────────────────────────────────────────
// MICROSOFT SSO LOGIN — admin login via Outlook/Microsoft account
// ─────────────────────────────────────────────

/**
 * GET /api/auth/microsoft-login
 * Redirects browser to Microsoft OAuth 2.0 consent screen for SSO
 */
app.get('/api/auth/microsoft-login', (req, res) => {
  if (!CFG.MICROSOFT_CLIENT_ID) {
    return res.status(503).send('Microsoft SSO not configured. Set MICROSOFT_CLIENT_ID in environment variables.');
  }
  const params = new URLSearchParams({
    client_id    : CFG.MICROSOFT_CLIENT_ID,
    response_type: 'code',
    redirect_uri : CFG.MICROSOFT_REDIRECT_URI,
    response_mode: 'query',
    scope        : 'openid profile email User.Read',
    state        : crypto.randomBytes(16).toString('hex')
  });
  res.redirect(`https://login.microsoftonline.com/${CFG.MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?` + params.toString());
});

/**
 * GET /api/auth/microsoft-callback
 * Microsoft redirects here with a code — we exchange it for tokens,
 * query MS Graph for the user's email, verify it, and issue a JWT.
 */
app.get('/api/auth/microsoft-callback', async (req, res) => {
  const { code, error, error_description } = req.query;
  if (error || !code) {
    console.error('[microsoft-sso] Auth error:', error_description || error);
    return res.redirect('/login.html?error=microsoft_cancelled');
  }
  try {
    const tokenParams = new URLSearchParams({
      client_id    : CFG.MICROSOFT_CLIENT_ID,
      scope        : 'openid profile email User.Read',
      code,
      redirect_uri : CFG.MICROSOFT_REDIRECT_URI,
      grant_type   : 'authorization_code',
      client_secret: CFG.MICROSOFT_CLIENT_SECRET
    }).toString();

    // 1. Exchange authorization code for token
    const tokenData = await new Promise((resolve, reject) => {
      const req2 = https.request({
        hostname: 'login.microsoftonline.com',
        path    : `/${CFG.MICROSOFT_TENANT_ID}/oauth2/v2.0/token`,
        method  : 'POST',
        headers : {
          'Content-Type'  : 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(tokenParams)
        }
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            if (r.statusCode >= 400) reject(new Error(parsed.error_description || parsed.error || 'HTTP ' + r.statusCode));
            else resolve(parsed);
          } catch(e) { reject(e); }
        });
      });
      req2.on('error', reject);
      req2.write(tokenParams);
      req2.end();
    });

    if (!tokenData.access_token) {
      console.error('[microsoft-sso] Token response contained no access token');
      return res.redirect('/login.html?error=microsoft_token_failed');
    }

    // 2. Query Microsoft Graph API to fetch profile details
    const profile = await new Promise((resolve, reject) => {
      const req3 = https.request({
        hostname: 'graph.microsoft.com',
        path    : '/v1.0/me',
        method  : 'GET',
        headers : { 'Authorization': 'Bearer ' + tokenData.access_token }
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try {
            const json = JSON.parse(d);
            if (r.statusCode >= 400) reject(new Error(json.error?.message || 'Graph API ' + r.statusCode));
            else resolve(json);
          } catch(e) { reject(e); }
        });
      });
      req3.on('error', reject);
      req3.end();
    });

    const userEmail = (profile.mail || profile.userPrincipalName || '').toLowerCase();
    
    // 3. Enforce matching email security constraint
    if (!userEmail || userEmail !== CFG.SUPER_ADMIN_EMAIL.toLowerCase()) {
      console.warn('[microsoft-sso] Unauthorised Azure AD login attempt:', userEmail);
      return res.redirect('/login.html?error=microsoft_unauthorised');
    }

    // 4. Issue JWT, store as one-time code, redirect safely (no token in URL)
    const token = makeToken({ email: userEmail, role: 'superadmin' });
    const ssoCode = crypto.randomBytes(32).toString('hex');
    ssoCodeStore.set(ssoCode, { token, email: userEmail, role: 'superadmin', expires: Date.now() + 90000 });
    logSecurityEvent('sso_login', userEmail, req, { provider: 'microsoft' });
    res.redirect('/admin?code=' + ssoCode);

  } catch (err) {
    console.error('[microsoft-sso] OAuth Callback processing failed:', err.message);
    res.redirect('/login.html?error=microsoft_error');
  }
});

// ─────────────────────────────────────────────
// ROUTES — JOBS
// ─────────────────────────────────────────────

/** GET /api/jobs  — public, active jobs only */
app.get('/api/jobs', async (req, res) => {
  try {
    let query = { status: 'active' };
    const { sector, type, location } = req.query;
    if (sector)   query.sector = sector;
    if (type)     query.type   = type;
    if (location) query.location = { $regex: location.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };

    const jobs = await Job.find(query).sort({ createdAt: -1 });
    res.json(jobs);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch jobs' }); }
});

/** GET /api/jobs/all — all jobs (auth required) */
app.get('/api/jobs/all', requireAuth, async (req, res) => {
  try {
    const jobs = await Job.find().sort({ createdAt: -1 });
    res.json(jobs);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch jobs' }); }
});

/** GET /api/jobs/:id — single public job by ID */
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Job.findOne({ id: req.params.id, status: 'active' });
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    res.json(job);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch job' }); }
});

/** POST /api/jobs — create job (auth required) */
app.post('/api/jobs', requireAuth, async (req, res) => {
  const { title, pay, sector, type, location, desc, req: requirements, status, imageBase64, closingDate, seoKeywords, seoDesc, isCorporate, workplace } = req.body;
  if (!title || !pay) return res.status(400).json({ error: 'Title and pay are required.' });

  let imageUrl = null;
  if (imageBase64) {
    try {
      const uploaded = await cloudinaryUpload(imageBase64, 'covenantcrest/jobs', `job-${uid()}`);
      imageUrl = uploaded.url;
    } catch (e) { console.error('Cloudinary upload failed:', e.message); }
  }

  try {
    const job = new Job({
      id       : uid(),
      title    : sanitise(title, 120),
      pay      : sanitise(pay,   60),
      sector   : sanitise(sector || 'care',       30),
      type     : sanitise(type   || 'full-time',  30),
      location : sanitise(location || '', 100),
      desc     : sanitise(desc     || '', 8000),
      req      : sanitise(requirements || '', 5000),
      status   : ['active', 'inactive'].includes(status) ? status : 'active',
      imageUrl,
      closingDate,
      seoKeywords,
      seoDesc,
      isCorporate : isCorporate === true || isCorporate === 'true',
      workplace   : sanitise(workplace || '', 20),
    });
    await job.save();

    // ── Fire job alerts (non-blocking) ────────────────────────────
    if (job.status === 'active') {
      JobAlert.find().then(alerts => {
        const matching = alerts.filter(a =>
          !a.sectors || a.sectors.length === 0 || a.sectors.includes(job.sector)
        );
        matching.forEach(alert => {
          const unsubUrl = `https://www.covenantcrest.co.uk/api/job-alerts/unsubscribe/${alert.token}`;
          sendEmail({ ...emailTpl.jobAlertEmail({ email: alert.email, job, unsubscribeUrl: unsubUrl }), from: 'recruitment@covenantcrest.co.uk' })
            .catch(e => console.error('[JobAlert] Email failed for', alert.email, e.message));
        });
        if (matching.length) console.log(`[JobAlert] Fired ${matching.length} alert emails for new job: ${job.title}`);
      }).catch(e => console.error('[JobAlert] Failed to fetch alerts:', e.message));
    }

    res.status(201).json(job);
  } catch(e) { res.status(500).json({ error: 'Failed to create job' }); }
});

/** PUT /api/jobs/:id — update job */
app.put('/api/jobs/:id', requireAuth, async (req, res) => {
  try {
    const { imageBase64, ...rest } = req.body;
    let updateData = { ...rest };
    
    if (imageBase64) {
      try {
        const up = await cloudinaryUpload(imageBase64, 'covenantcrest/jobs', `job-${req.params.id}`);
        updateData.imageUrl = up.url;
      } catch (e) { console.error('Cloudinary update failed:', e.message); }
    }

    const job = await Job.findOneAndUpdate({ id: req.params.id }, updateData, { new: true });
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    res.json(job);
  } catch(e) { res.status(500).json({ error: 'Failed to update job' }); }
});

/** DELETE /api/jobs/:id */
app.delete('/api/jobs/:id', requireAuth, async (req, res) => {
  try {
    const job = await Job.findOne({ id: req.params.id });
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    await Job.deleteOne({ id: req.params.id });
    // Clean up associated Cloudinary image (non-blocking, errors silently ignored)
    if (job.imageUrl) cloudinaryDelete(job.imageUrl).catch(() => {});
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete job' }); }
});

// ─────────────────────────────────────────────
// ROUTES — CONTACTS / ENQUIRIES
// ─────────────────────────────────────────────

/** GET /api/contacts — protected */
app.get('/api/contacts', requireAuth, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch enquiries' }); }
});

/**
 * POST /api/contacts — public
 * Used by website forms OR Netlify webhook forwarding
 * Sends email alert + auto-reply
 */
app.post('/api/contacts', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  try {
    const contact = new Contact({
      id     : uid(),
      name   : sanitise(req.body.name || req.body.first_name || '', 120),
      email  : sanitise(req.body.email || '', 200),
      phone  : sanitise(req.body.phone || '', 30),
      company: sanitise(req.body.company || '', 200), // Bug 7: Extract structured company field
      type   : sanitise(req.body.enquiry_type || req.body.type || 'general', 40),
      message: sanitise(req.body.message || req.body.notes || '', 3000),
      source : sanitise(req.body['form-name'] || 'api', 50),
      status : 'new',
    });
    await contact.save();

    // Determine dynamic sender email based on enquiry type
    let fromEmail = CFG.EMAIL_FROM;
    if (contact.type === 'haulage') fromEmail = 'haulage@covenantcrest.co.uk';
    else if (contact.type === 'trade') fromEmail = 'trade@covenantcrest.co.uk';
    else if (contact.type === 'general' || contact.type === 'contact' || contact.type === 'about') fromEmail = 'info@covenantcrest.co.uk';

    // Fire emails + CRM Sync (non-blocking)
    Promise.allSettled([
      sendEmail(emailTpl.newEnquiryAlert(contact)),
      contact.email ? sendEmail({
        ...emailTpl.enquiryAutoReply(contact),
        to: contact.email,
        from: fromEmail,
      }) : Promise.resolve(),
      syncToHubSpot(contact, 'contact').catch(e => console.error('[HubSpot] Contact CRM Sync failed:', e.message))
    ]).then(results => {
    results.forEach((r, i) => {
      if (r.status === 'rejected') console.error('Email/CRM error #' + i, r.reason?.message);
    });
  });

  res.status(201).json({ success: true, id: contact.id });
  } catch(e) { res.status(500).json({ error: 'Failed to save enquiry' }); }
});

/** PUT /api/contacts/:id — mark read / update status */
app.put('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const { status, read, notes, adminNotes } = req.body;
    const update = {};
    if (status     !== undefined) update.status     = sanitise(String(status), 40);
    if (read       !== undefined) update.read       = !!read;
    if (notes      !== undefined) update.notes      = sanitise(String(notes), 3000);
    if (adminNotes !== undefined) update.adminNotes = sanitise(String(adminNotes), 3000);
    const contact = await Contact.findOneAndUpdate({ id: req.params.id }, update, { new: true });
    if (!contact) return res.status(404).json({ error: 'Enquiry not found.' });
    res.json(contact);
  } catch(e) { res.status(500).json({ error: 'Failed to update enquiry' }); }
});

/** DELETE /api/contacts/:id — super admin only */
app.delete('/api/contacts/:id', requireSuperAdmin, async (req, res) => {
  try {
    const result = await Contact.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Enquiry not found.' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete enquiry' }); }
});

// ─────────────────────────────────────────────
// ROUTES — JOB ALERTS
// ─────────────────────────────────────────────

/**
 * POST /api/job-alerts — public
 * Body: { email, sectors: ['care','security',...] }
 * Subscribes an email to job alerts. Sectors is optional ([] = all).
 */
app.post('/api/job-alerts', rateLimit(60 * 60 * 1000, 5), async (req, res) => {
  const email   = sanitise(req.body.email || '', 200).toLowerCase();
  const sectors = Array.isArray(req.body.sectors)
    ? req.body.sectors.map(s => sanitise(String(s), 30)).filter(Boolean)
    : [];

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'A valid email address is required.' });
  }

  try {
    // Upsert — update sectors if email already subscribed
    const existing = await JobAlert.findOne({ email });
    if (existing) {
      existing.sectors = sectors;
      await existing.save();
      return res.json({ success: true, message: 'Your job alert preferences have been updated.' });
    }

    const alert = new JobAlert({
      id     : uid(),
      email,
      sectors,
      token  : crypto.randomBytes(32).toString('hex'),
    });
    await alert.save();

    // Send confirmation email (non-blocking)
    sendEmail({
      to     : email,
      subject: 'Job Alert Confirmed — Covenant Crest',
      html   : `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
        <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
          <h2 style="color:#C9A84C;margin:0;font-size:20px;">Job Alert Set ✓</h2>
        </div>
        <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
          <p style="font-size:14px;color:#333;line-height:1.7;">You're now signed up for job alerts${sectors.length ? ' in: <strong>' + sectors.join(', ') + '</strong>' : ' across all sectors'}.</p>
          <p style="font-size:14px;color:#333;line-height:1.7;">We'll email you as soon as a matching job is posted. In the meantime, browse our <a href="https://www.covenantcrest.co.uk/recruitment" style="color:#C9A84C;">live job listings</a>.</p>
          <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
          <p style="font-size:11px;color:#999;margin:0;">Not you? <a href="https://www.covenantcrest.co.uk/api/job-alerts/unsubscribe/${alert.token}" style="color:#C9A84C;">Unsubscribe immediately</a>.</p>
        </div>
      </div>`,
      from   : 'recruitment@covenantcrest.co.uk',
    }).catch(e => console.error('[JobAlert] Confirmation email failed:', e.message));

    res.status(201).json({ success: true, message: 'Job alert created! Check your email for confirmation.' });
  } catch(e) {
    console.error('[JobAlert] Save failed:', e.message);
    res.status(500).json({ error: 'Failed to save job alert.' });
  }
});

/**
 * GET /api/job-alerts/unsubscribe/:token — public one-click unsubscribe
 */
app.get('/api/job-alerts/unsubscribe/:token', async (req, res) => {
  try {
    const result = await JobAlert.deleteOne({ token: req.params.token });
    if (result.deletedCount === 0) {
      return res.send('<html><body style="font-family:Arial;text-align:center;padding:80px;background:#f8f8f8;"><h2 style="color:#C9A84C;">Alert not found</h2><p>This unsubscribe link may have already been used.</p><a href="https://www.covenantcrest.co.uk/recruitment">Browse Jobs</a></body></html>');
    }
    res.send('<html><body style="font-family:Arial;text-align:center;padding:80px;background:#f8f8f8;"><h2 style="color:#0D1B2A;">Unsubscribed ✓</h2><p style="color:#555;">You\'ve been removed from job alerts. You won\'t receive any more emails from us.</p><p><a href="https://www.covenantcrest.co.uk/recruitment" style="color:#C9A84C;">Browse current jobs</a></p></body></html>');
  } catch(e) {
    res.status(500).send('Error processing unsubscribe. Please contact info@covenantcrest.co.uk');
  }
});

/**
 * GET /api/job-alerts — admin view of all subscribers
 */
app.get('/api/job-alerts', requireSuperAdmin, async (req, res) => {
  try {
    const alerts = await JobAlert.find().sort({ createdAt: -1 }).select('-token');
    res.json(alerts);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch job alerts' }); }
});

/**
 * DELETE /api/job-alerts/:id — super admin remove subscriber
 */
app.delete('/api/job-alerts/:id', requireSuperAdmin, async (req, res) => {
  try {
    await JobAlert.deleteOne({ id: req.params.id });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete alert' }); }
});



/** GET /api/applications/all — protected */
app.get('/api/applications/all', requireAuth, async (req, res) => {
  try {
    const apps = await Application.find().sort({ createdAt: -1 });
    res.json(apps);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch applications' }); }
});

/** GET /api/applications — Super Admin alias */
app.get('/api/applications', requireSuperAdmin, async (req, res) => {
  try {
    const apps = await Application.find().sort({ createdAt: -1 });
    res.json(apps);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch applications' }); }
});

/** POST /api/applications — public */
app.post('/api/applications', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
  try {
    const b = req.body;
    const cvBase64   = b.cvBase64   || null;
    const cvFileName = b.cvFileName || null;

    // Whitelist every field a candidate is allowed to submit — nothing else gets into the DB
    const safe = {
      first_name   : sanitise(b.first_name,    80),
      last_name    : sanitise(b.last_name,     80),
      email        : sanitise(b.email,         200),
      phone        : sanitise(b.phone,         30),
      sector       : sanitise(b.sector,        40),
      job_title    : sanitise(b.job_title,     120),
      availability : sanitise(b.availability,  40),
      notes        : sanitise(b.notes,         1000),
      rtw_status   : sanitise(b.rtw_status,    40),
      visa_details : sanitise(b.visa_details,  200),
      is_veteran   : sanitise(b.is_veteran,    10),
      assistance   : sanitise(b.assistance,    300),
      postcode     : sanitise(b.postcode,      20),
      // Dynamic Vetting whitelists (Bug 11 backend mapping)
      dbs_cert_number    : sanitise(b.dbs_cert_number, 50),
      sia_licence_number : sanitise(b.sia_licence_number, 50),
      sia_expiry_date    : sanitise(b.sia_expiry_date, 30),
      // Sector compliance fields
      nmc_pin            : sanitise(b.nmc_pin, 50),
      cscs_number        : sanitise(b.cscs_number, 50),
      food_hygiene_level : sanitise(b.food_hygiene_level || b.hygiene_cert, 100),
      hgv_license        : sanitise(b.hgv_license || b.hgv_number, 100),
    };

    // 1. Enforce Blacklist
    const isBlacklisted = await Application.exists({
      email: safe.email,
      status: 'blacklisted'
    });

    const entry = new Application({
      id: uid(),
      ...safe,
      status: isBlacklisted ? 'blacklisted' : 'new',
    });

    if (cvBase64) {
      try {
        let publicId = `cv-${entry.id}`;
        // Preserve extension if provided to prevent "corrupted" downloads
        if (cvFileName && cvFileName.includes('.')) {
          const ext = cvFileName.split('.').pop();
          if (ext) publicId += `.${ext}`;
        }
        const up = await cloudinaryUpload(cvBase64, 'covenantcrest/cvs', publicId, 'raw');
        entry.cvUrl = up.url;
      } catch (e) { console.error('CV upload failed:', e.message); }
    }

    await entry.save();
    
    // Non-blocking emails + CRM Sync
    Promise.allSettled([
      sendEmail(emailTpl.newApplicationAlert(entry, cvBase64, cvFileName)),
      entry.email ? sendEmail({ ...emailTpl.applicationAutoReply(entry), to: entry.email, from: 'recruitment@covenantcrest.co.uk' }) : Promise.resolve(),
      syncToHubSpot(entry, 'candidate').catch(e => console.error('[HubSpot] Candidate CRM Sync failed:', e.message))
    ]);

    res.status(201).json(entry);
  } catch(e) { res.status(500).json({ error: 'Failed to save application' }); }
});

/** PUT /api/applications/:id — update status */
app.put('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const allowed = [
      'status', 'notes', 'adminNotes', 'matchScore', 'rating',
      'dbs_level', 'dbs_cert_number', 'dbs_expiry_date',
      'sia_licence_number', 'sia_expiry_date',
      'rtw_doc_type', 'rtw_expiry_date', 'rtw_verified',
      'manual_handling_cert', 'compliance_notes', 'compliance_status',
      'postcode', 'rtw_status', 'visa_details', 'is_veteran', 'assistance',
      'nmc_pin', 'cscs_number', 'food_hygiene_level', 'hgv_license',
      'rejectionReason', 'requestedDocs'
    ];
    const update = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        update[key] = typeof req.body[key] === 'string'
          ? sanitise(req.body[key], 500)
          : req.body[key];
      }
    }
    
    // Find candidate first to track status transitions
    const appDoc = await Application.findOne({ id: req.params.id });
    if (!appDoc) return res.status(404).json({ error: 'Application not found.' });

    const statusTransitionedToRejected = 
      update.status === 'rejected' && appDoc.status !== 'rejected';

    // Apply updates and save
    Object.assign(appDoc, update);
    const savedApp = await appDoc.save();

    // Trigger rejection email asynchronously if transitioned
    if (statusTransitionedToRejected && savedApp.email) {
      const candidateName = savedApp.first_name || 'Candidate';
      const jobTitle = savedApp.job_title || 'the applied role';
      const rejectSubject = `Application Status Update: ${savedApp.job_title || 'Your Application'} — Covenant Crest Group`;
      const rejectHtml = `
        <div style="font-family:Arial,sans-serif;padding:32px;background:#FAF9F6;color:#0D1B2A;border-radius:12px;border:1px solid #E8E4DC;max-width:600px;margin:0 auto;">
          <div style="text-align:center;border-bottom:2px solid #C9A84C;padding-bottom:20px;margin-bottom:24px;">
            <h2 style="color:#0D1B2A;margin:0;font-size:26px;">Covenant Crest Group</h2>
            <p style="color:#7A8694;margin:4px 0 0;font-size:12px;letter-spacing:0.15em;text-transform:uppercase;">Application Update</p>
          </div>
          <h3 style="color:#0D1B2A;font-size:18px;">Dear ${candidateName},</h3>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">Thank you for your interest in the <strong>${jobTitle}</strong> position with Covenant Crest Group and for taking the time to apply.</p>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">${savedApp.rejectionReason || 'We received a large number of applications from highly qualified candidates. After careful review of your CV and background details, we regret to inform you that we will not be moving forward with your application for this position.'}</p>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">We appreciate the time you invested in applying to Covenant Crest. We will retain your registration details in our talent pool database and will reach out to you if another opportunity arises that aligns with your skills and experience.</p>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">We wish you the very best in your job search and future career endeavors.</p>
          <br>
          <p style="font-size:14px;font-weight:600;color:#0D1B2A;margin:0;">Kind regards,</p>
          <p style="font-size:13px;color:#7A8694;margin:4px 0 0;">The Recruitment Team</p>
          <p style="font-size:13px;color:#C9A84C;font-weight:600;margin:2px 0 0;">Covenant Crest Group</p>
          
          <div style="border-top:1px solid #E8E4DC;margin-top:28px;padding-top:16px;text-align:center;font-size:11px;color:#9AA5B4;">
            Covenant Crest Group Ltd &bull; Registered in England & Wales Co. No. 16528951 &bull; Built on Promise.
          </div>
        </div>
      `;

      sendEmail({
        to: savedApp.email,
        subject: rejectSubject,
        html: rejectHtml,
        from: 'recruitment@covenantcrest.co.uk'
      }).catch(err => console.error('[reject-email] Failed to send rejection mail to:', savedApp.email, err.message));
    }

    // Trigger document request email asynchronously if transitioned to docs_requested
    const statusTransitionedToDocsRequested = 
      update.status === 'docs_requested' && appDoc.status !== 'docs_requested';
      
    if (statusTransitionedToDocsRequested && savedApp.email) {
      const candidateName = savedApp.first_name || 'Candidate';
      const docsRequestedText = savedApp.requestedDocs || 'Missing CV or compliance certifications.';
      const docsSubject = `Action Required: Missing Information for your Covenant Crest Application - ${savedApp.job_title || 'Role'}`;
      const docsHtml = `
        <div style="font-family:Arial,sans-serif;padding:32px;background:#FAF9F6;color:#0D1B2A;border-radius:12px;border:1px solid #E8E4DC;max-width:600px;margin:0 auto;">
          <div style="text-align:center;border-bottom:2px solid #C9A84C;padding-bottom:20px;margin-bottom:24px;">
            <h2 style="color:#0D1B2A;margin:0;font-size:26px;">Covenant Crest Group</h2>
            <p style="color:#7A8694;margin:4px 0 0;font-size:12px;letter-spacing:0.15em;text-transform:uppercase;">Information Request</p>
          </div>
          <h3 style="color:#0D1B2A;font-size:18px;">Dear ${candidateName},</h3>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">Thank you for your interest in the <strong>${savedApp.job_title || 'applied role'}</strong> position with Covenant Crest Group.</p>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">While reviewing your application, we noted that we require some additional documentation or details to proceed with your vetting process:</p>
          <div style="background:#FFFDF0;padding:16px;border-left:4px solid #C9A84C;border-radius:4px;margin:18px 0;font-size:14px;line-height:1.75;color:#0D1B2A;font-family:monospace;">
            <strong>Requested items:</strong><br>
            ${docsRequestedText.split('\n').join('<br>')}
          </div>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">Please reply directly to this email and attach the requested files or provide the information as soon as possible so we can move your application forward.</p>
          <br>
          <p style="font-size:14px;font-weight:600;color:#0D1B2A;margin:0;">Kind regards,</p>
          <p style="font-size:13px;color:#7A8694;margin:4px 0 0;">The Recruitment Team</p>
          <p style="font-size:13px;color:#C9A84C;font-weight:600;margin:2px 0 0;">Covenant Crest Group</p>
          
          <div style="border-top:1px solid #E8E4DC;margin-top:28px;padding-top:16px;text-align:center;font-size:11px;color:#9AA5B4;">
            Covenant Crest Group Ltd &bull; Registered in England & Wales Co. No. 16528951 &bull; Built on Promise.
          </div>
        </div>
      `;

      sendEmail({
        to: savedApp.email,
        subject: docsSubject,
        html: docsHtml,
        from: 'recruitment@covenantcrest.co.uk'
      }).catch(err => console.error('[docs-request-email] Failed to send email to:', savedApp.email, err.message));
    }

    res.json(savedApp);
  } catch(e) { 
    console.error('Update application error:', e.message);
    res.status(500).json({ error: 'Failed to update application' }); 
  }
});

/** DELETE /api/applications/:id */
app.delete('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const result = await Application.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Application not found.' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete application' }); }
});

/** GET /api/compliance/expiring — hired workers with docs expiring within 90 days (auth) */
app.get('/api/compliance/expiring', requireAuth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const limit = new Date(today.getTime() + 90 * 24 * 60 * 60 * 1000);
    const limitStr = limit.toISOString().slice(0, 10);

    const workers = await Application.find({
      status: 'hired',
      $or: [
        { dbs_expiry_date:      { $exists: true, $ne: '', $lte: limitStr } },
        { sia_expiry_date:      { $exists: true, $ne: '', $lte: limitStr } },
        { rtw_expiry_date:      { $exists: true, $ne: '', $lte: limitStr } },
        { manual_handling_cert: { $exists: true, $ne: '', $lte: limitStr } },
      ],
    }).sort({ createdAt: -1 });

    res.json(workers);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch compliance data' }); }
});

// ─────────────────────────────────────────────
// ROUTES — IMAGE UPLOAD (standalone)
// ─────────────────────────────────────────────

/**
 * POST /api/upload
 * Body: { base64: "...", folder: "covenantcrest/general", publicId: "optional" }
 * Protected — any authenticated user
 */
app.post('/api/upload', requireAuth, async (req, res) => {
  const { base64, folder = 'covenantcrest/general', publicId } = req.body;
  if (!base64) return res.status(400).json({ error: 'base64 image data is required.' });
  try {
    const result = await cloudinaryUpload(base64, folder, publicId || uid());
    res.json({ success: true, url: result.url, publicId: result.publicId });
  } catch (e) {
    console.error('Upload error:', e.message);
    res.status(500).json({ error: e.message || 'Upload failed.' });
  }
});

// ─────────────────────────────────────────────
// ROUTES — USER MANAGEMENT (Super Admin only)
// ─────────────────────────────────────────────

/** GET /api/users */
app.get('/api/users', requireSuperAdmin, async (req, res) => {
  try {
    const users = await User.find({ role: 'employee' }).select('-password').sort({ createdAt: 1 });
    res.json([
      { id: 'superadmin', email: CFG.SUPER_ADMIN_EMAIL, role: 'superadmin', created: null },
      ...users.map(u => ({ id: u.id, email: u.email, role: u.role, created: u.created })),
    ]);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

/** POST /api/users — create employee */
app.post('/api/users', requireSuperAdmin, async (req, res) => {
  const { email = '', password = '' } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required.' });
  if (!password || password.length < 8)  return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const emailLc = email.trim().toLowerCase();
  if (emailLc === CFG.SUPER_ADMIN_EMAIL.toLowerCase())
    return res.status(409).json({ error: 'This email is reserved.' });

  try {
    const existing = await User.findOne({ email: emailLc });
    if (existing) return res.status(409).json({ error: 'An account with this email already exists.' });

    const hashed = await hashPassword(password);
    const user = new User({
      id      : uid(),
      email   : emailLc,
      password: hashed,
      role    : 'employee',
      created : new Date(),
    });
    await user.save();
    res.status(201).json({ id: user.id, email: user.email, role: user.role, created: user.created });
  } catch(e) {
    if (e.code === 11000) return res.status(409).json({ error: 'An account with this email already exists.' });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

/** DELETE /api/users/:id */
app.delete('/api/users/:id', requireSuperAdmin, async (req, res) => {
  if (req.params.id === 'superadmin')
    return res.status(403).json({ error: 'Cannot delete the Super Admin account.' });
  try {
    const result = await User.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete user' }); }
});

// ─────────────────────────────────────────────
// ROUTES — NETLIFY WEBHOOK
// ─────────────────────────────────────────────

/**
 * POST /api/netlify-webhook
 * Configure in: Netlify → Forms → Notifications → Outgoing webhook
 * URL: https://your-render-service.onrender.com/api/netlify-webhook
 * Optional: set webhook secret in Netlify and match NETLIFY_WEBHOOK_SECRET env var
 */
app.post('/api/netlify-webhook', async (req, res) => {
  // Verify signature if secret is configured — use raw body to match Netlify's HMAC
  if (CFG.NETLIFY_SECRET) {
    const sig      = req.headers['x-webhook-signature'] || '';
    const rawBody  = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const expected = crypto.createHmac('sha256', CFG.NETLIFY_SECRET).update(rawBody).digest('hex');
    
    const expectedSig = `sha256=${expected}`;
    if (sig.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return res.status(401).json({ error: 'Invalid webhook signature.' });
    }
  }

  try {
  const payload = req.body;
  const data    = payload.data || payload;
  const formName = sanitise(payload.form_name || data.form_name || '', 80);

  // ── Route candidate-apply to Applications ────────────────────
  if (formName === 'candidate-apply') {
    const entry = new Application({
      id          : uid(),
      first_name  : sanitise(data.first_name || data.name?.split(' ')[0] || '', 60),
      last_name   : sanitise(data.last_name  || data.name?.split(' ').slice(1).join(' ') || '', 60),
      email       : sanitise(data.email       || '', 200),
      phone       : sanitise(data.phone       || '', 30),
      sector      : sanitise(data.sector      || '', 40),
      job_id      : sanitise(data.job_id      || '', 30),
      job_title   : sanitise(data.job_title   || data['job-title'] || '', 120),
      availability: sanitise(data.availability || '', 50),
      notes       : sanitise(data.notes || data.message || '', 2000),
      cvUrl       : null,
      status      : 'new',
      source      : 'netlify-form',
      // Map other whitelisted properties if available
      postcode    : sanitise(data.postcode || '', 20),
      rtw_status  : sanitise(data.rtw_status || '', 40),
      visa_details: sanitise(data.visa_details || '', 200),
      is_veteran  : sanitise(data.is_veteran || '', 10),
      assistance  : sanitise(data.assistance || '', 300),
      nmc_pin     : sanitise(data.nmc_pin || '', 50),
      cscs_number : sanitise(data.cscs_number || '', 50),
      food_hygiene_level: sanitise(data.food_hygiene_level || data.hygiene_cert || '', 100),
      hgv_license : sanitise(data.hgv_license || data.hgv_number || '', 100),
    });
    await entry.save();

    // Alert to admin + confirmation to candidate + HubSpot CRM sync
    Promise.allSettled([
      sendEmail(emailTpl.newApplicationAlert(entry)),
      entry.email ? sendEmail({ ...emailTpl.applicationAutoReply(entry), to: entry.email, from: 'recruitment@covenantcrest.co.uk' }) : Promise.resolve(),
      syncToHubSpot(entry, 'candidate').catch(e => console.error('[HubSpot] Webhook Candidate CRM Sync failed:', e.message))
    ]);

    return res.json({ received: true, id: entry.id, routed: 'applications' });
  }

  // ── All other forms → Contact Enquiries ──────────────────────
  let computedMessage = data.message || data.notes || data.details || '';
  
  // Structured mapping to prevent B2B / quote / enquiry data loss
  if (formName === 'recruitment-request-staff') {
    const parts = [];
    if (data.service_model) parts.push(`Service Model: ${data.service_model}`);
    if (data.sector) parts.push(`Sector: ${data.sector}`);
    if (data.shift_patterns) parts.push(`Shift Patterns: ${data.shift_patterns}`);
    if (data.job_title) parts.push(`Job Title: ${data.job_title}`);
    if (data.workers_needed) parts.push(`Workers Needed: ${data.workers_needed}`);
    if (data.start_date) parts.push(`Start Date: ${data.start_date}`);
    if (data.postcode) parts.push(`Site Postcode: ${data.postcode}`);
    if (computedMessage) parts.push(`Additional Notes: ${computedMessage}`);
    computedMessage = parts.join('\n');
  } else if (formName === 'haulage-quote') {
    const parts = [];
    if (data.collection) parts.push(`Collection: ${data.collection}`);
    if (data.delivery) parts.push(`Delivery: ${data.delivery}`);
    if (data.load_type) parts.push(`Load Type: ${data.load_type}`);
    if (data.weight) parts.push(`Weight: ${data.weight}`);
    if (computedMessage) parts.push(`Details: ${computedMessage}`);
    computedMessage = parts.join('\n');
  } else if (formName === 'trade-enquiry') {
    const parts = [];
    if (data.product) parts.push(`Product: ${data.product}`);
    if (data.quantity) parts.push(`Quantity: ${data.quantity}`);
    if (data.frequency) parts.push(`Frequency: ${data.frequency}`);
    if (data.incoterm) parts.push(`Incoterm: ${data.incoterm}`);
    if (computedMessage) parts.push(`Details: ${computedMessage}`);
    computedMessage = parts.join('\n');
  } else if (formName === 'compliance-pack-request') {
    const parts = [];
    if (data.role) parts.push(`Requestor Role: ${data.role}`);
    computedMessage = parts.join('\n');
  }

  const contact = new Contact({
    id     : uid(),
    name   : sanitise(data.full_name || data.name || data.first_name || data.contact_name || '', 120),
    email  : sanitise(data.email || (data.contact && data.contact.includes('@') ? data.contact : '') || '', 200),
    phone  : sanitise(data.phone || (data.contact && !data.contact.includes('@') ? data.contact : '') || '', 30),
    company: sanitise(data.company || data.company_name || '', 200),
    type   : sanitise(data.enquiry_type || data.type || formName || 'general', 40),
    message: sanitise(computedMessage, 3000),
    source : sanitise(formName || 'netlify-webhook', 50),
    status : 'new',
  });
  await contact.save();

  // Determine dynamic sender email based on enquiry type or form name
  let fromEmail = CFG.EMAIL_FROM;
  if (contact.type === 'haulage' || formName === 'haulage-quote') fromEmail = 'haulage@covenantcrest.co.uk';
  else if (contact.type === 'trade' || formName === 'trade-enquiry') fromEmail = 'trade@covenantcrest.co.uk';
  else if (contact.type === 'general' || contact.type === 'contact' || contact.type === 'about_enquiry') fromEmail = 'info@covenantcrest.co.uk';
  else if (formName === 'recruitment-request-staff') fromEmail = 'recruitment@covenantcrest.co.uk';

  Promise.allSettled([
    sendEmail(emailTpl.newEnquiryAlert(contact)),
    contact.email ? sendEmail({ ...emailTpl.enquiryAutoReply(contact), to: contact.email, from: fromEmail }) : Promise.resolve(),
    syncToHubSpot(contact, 'contact').catch(e => console.error('[HubSpot] Webhook Contact CRM Sync failed:', e.message))
  ]);

  res.json({ received: true, id: contact.id, routed: 'contacts' });
  } catch(e) {
    console.error('Webhook handler error:', e.message);
    return res.status(500).json({ error: 'Webhook processing failed.' });
  }
});

// ─────────────────────────────────────────────
// HUBSPOT CRM INTEGRATION (API v3)
// ─────────────────────────────────────────────

/**
 * Synchronises Client requests and Candidate registration details directly
 * to HubSpot CRM as contacts using a Private App Access Token.
 */
async function syncToHubSpot(data, type) {
  if (!CFG.HUBSPOT_ACCESS_TOKEN) {
    console.log('[HubSpot] Access Token not set. Skipping CRM synchronization.');
    return null;
  }

  // Map fields logically (HubSpot CRM standard properties)
  const properties = {
    firstname: data.first_name || data.name?.split(' ')[0] || 'Unknown',
    lastname: data.last_name || data.name?.split(' ').slice(1).join(' ') || 'Contact',
    email: data.email || '',
    phone: data.phone || '',
  };

  if (type === 'contact') {
    properties.description = `[Client Staffing/General Enquiry]\nType: ${data.type || 'General'}\nSource: ${data.source || 'Website'}\nCompany: ${data.company || 'Not provided'}\n\nMessage:\n${data.message || ''}`;
    if (data.company) {
      properties.company = data.company;
    }
  } else if (type === 'candidate') {
    properties.jobtitle = data.job_title || 'Applicant';
    properties.description = `[Candidate Application Portal]\nSector: ${data.sector || 'General'}\nAvailability: ${data.availability || 'Not provided'}\nCV Cloudinary Link: ${data.cvUrl || 'None'}\n\nCompliance & Vetting Vitals:\nDBS Certificate: ${data.dbs_cert_number || 'N/A'}\nSIA License: ${data.sia_licence_number || 'N/A'}\nFood Hygiene Expiry/Level: ${data.food_hygiene_level || 'N/A'}\nHGV/CPC License details: ${data.hgv_license || 'N/A'}\n\nCandidate Personal Statement/Notes:\n${data.notes || ''}`;
  }

  const body = JSON.stringify({ properties });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.hubapi.com',
      path: '/crm/v3/objects/contacts',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CFG.HUBSPOT_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let d = '';
      res.on('data', chunk => d += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (res.statusCode >= 400) {
            console.error('[HubSpot] CRM Sync Failed:', res.statusCode, d);
            reject(new Error(parsed.message || 'CRM API Error ' + res.statusCode));
          } else {
            console.log('[HubSpot] Successfully synced contact ID:', parsed.id);
            resolve(parsed);
          }
        } catch(e) { reject(e); }
      });
    });
    req.on('error', (e) => {
      console.error('[HubSpot] Network error during CRM sync:', e.message);
      reject(e);
    });
    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────
// TRANSACTIONAL EMAIL ENGINE (Resend)
// ─────────────────────────────────────────────

/**
 * Direct email dispatcher utilizing the Resend API to deliver alerts
 * straight to your corporate Outlook inbox.
 */
async function sendEmail({ to, subject, html, from, attachments }) {
  if (!CFG.RESEND_API_KEY) {
    console.warn('[email] Resend API Key is not set. Outbound mail was bypassed:', subject);
    return Promise.resolve({ bypassed: true });
  }

  const fromAddress = from || CFG.EMAIL_FROM;
  const recipients = Array.isArray(to) ? to : [to];
  const payload = {
    from   : `Covenant Crest <${fromAddress}>`,
    to     : recipients,
    subject,
    html,
  };
  if (attachments && attachments.length > 0) {
    payload.attachments = attachments;
  }
  const body = JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.resend.com',
      path    : '/emails',
      method  : 'POST',
      headers : {
        'Authorization': `Bearer ${CFG.RESEND_API_KEY}`,
        'Content-Type' : 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let d = '';
      res.on('data', chunk => d += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(d);
          if (res.statusCode >= 400) {
            console.error('[resend] Mail Delivery Failed:', res.statusCode, d);
            return reject(new Error(json.message || 'Resend error: ' + d));
          }
          console.log('[resend] Email dispatched successfully to:', recipients.join(', '));
          resolve(json);
        } catch(e) { reject(e); }
      });
    });
    req.on('error', (e) => {
      console.error('[resend] Network error:', e.message);
      reject(e);
    });
    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────
// DIAGNOSTIC TESTING ENDPOINTS (Super Admin only)
// ─────────────────────────────────────────────

/**
 * POST /api/diagnostics/test-resend
 * Sends a test email to verify the Resend connection.
 */
app.post('/api/diagnostics/test-resend', requireSuperAdmin, async (req, res) => {
  try {
    const testResult = await sendEmail({
      to     : CFG.EMAIL_NOTIFY,
      subject: '✅ Covenant Crest — Resend Transactional Mail Test',
      html   : `<div style="font-family:Arial,sans-serif;padding:24px;background:#0D1B2A;color:#fff;border-radius:8px;"><h2 style="color:#C9A84C;margin:0 0 16px;">Test Successful</h2><p>Resend mail delivery engine is working perfectly for <strong>Covenant Crest Group Ltd</strong>.</p><p>Dispatched to: <strong>${CFG.EMAIL_NOTIFY}</strong></p><p>Sent: ${new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' })}</p></div>`,
    });
    res.json({ success: true, message: 'Test email sent to ' + CFG.EMAIL_NOTIFY, result: testResult });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * POST /api/diagnostics/test-hubspot
 * Pushes a mock contact to HubSpot to test credentials and pipeline sync.
 */
app.post('/api/diagnostics/test-hubspot', requireSuperAdmin, async (req, res) => {
  try {
    const testContact = {
      name: 'HubSpot Test Run',
      email: `test-${Date.now()}@covenantcrest.co.uk`,
      phone: '07000000000',
      type: 'Diagnostic Sync Test',
      message: 'This is an automated request verifying that the HubSpot Private App Token CRM sync is functional.',
      source: 'Admin Diagnostics Panel'
    };
    const syncResult = await syncToHubSpot(testContact, 'contact');
    res.json({ success: true, message: 'Mock contact pushed successfully to HubSpot CRM.', result: syncResult });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /api/auth/2fa-setup — Admin only
 * Returns the 2FA setup status and raw secret key for manual entry, or QR code URL
 */
app.get('/api/auth/2fa-setup', requireSuperAdmin, (req, res) => {
  const secret = CFG.SUPER_ADMIN_2FA_SECRET;
  if (!secret) {
    return res.json({ 
      enabled: false, 
      message: '2FA is not enabled. Add SUPER_ADMIN_2FA_SECRET to your Render environment variables to enable it.' 
    });
  }
  const email = CFG.SUPER_ADMIN_EMAIL;
  const issuer = 'Covenant Crest';
  const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
  res.json({
    enabled: true,
    secret: secret,
    qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUrl)}`
  });
});

// ─────────────────────────────────────────────
// MICROSOFT 365 GRAPH API INTEGRATION (Teams & Calendar)
// ─────────────────────────────────────────────

async function getMicrosoftAccessToken() {
  if (!CFG.MICROSOFT_CLIENT_ID || !CFG.MICROSOFT_CLIENT_SECRET) {
    throw new Error('Microsoft M365 Client ID and Client Secret are not configured in your environment.');
  }
  if (!CFG.MICROSOFT_TENANT_ID || CFG.MICROSOFT_TENANT_ID === 'common') {
    throw new Error('M365 scheduling requires a specific Microsoft Tenant ID (not "common"). Please set MICROSOFT_TENANT_ID in Render variables to your specific Entra directory ID or domain name (e.g., covenantcrest.co.uk).');
  }
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CFG.MICROSOFT_CLIENT_ID,
    client_secret: CFG.MICROSOFT_CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default'
  }).toString();

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'login.microsoftonline.com',
      path: `/${CFG.MICROSOFT_TENANT_ID}/oauth2/v2.0/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let d = '';
      res.on('data', chunk => d += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (res.statusCode >= 400) {
            reject(new Error(parsed.error_description || 'OAuth Token Error ' + res.statusCode));
          } else {
            resolve(parsed.access_token);
          }
        } catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * POST /api/interviews/schedule-teams
 * Schedules a Microsoft Teams video meeting interview via Graph API and books it on Outlook calendar.
 */
app.post('/api/interviews/schedule-teams', requireAuth, async (req, res) => {
  try {
    const { candidateName, candidateEmail, jobTitle, dateTime, durationMinutes } = req.body;
    if (!candidateName || !candidateEmail || !dateTime) {
      return res.status(400).json({ error: 'Candidate Name, Email and Date/Time are required.' });
    }

    const duration = durationMinutes ? parseInt(durationMinutes) : 30;
    const startDateTime = new Date(dateTime);
    const endDateTime = new Date(startDateTime.getTime() + duration * 60 * 1000);

    const organiserEmail = 'recruitment@covenantcrest.co.uk';

    // Fallback sandbox / diagnostic mode if Microsoft SSO Client ID is not configured
    if (!CFG.MICROSOFT_CLIENT_ID || !CFG.MICROSOFT_CLIENT_SECRET) {
      console.log('[M365] Microsoft SSO is not configured. Running in fallback sandbox diagnostics mode.');
      
      const mockTeamsLink = `https://teams.live.com/meet/943${Math.floor(Math.random() * 900000000)}?p=ccPortalMock`;
      
      // Send invitation alert email using our normal email alert engine (Resend)
      const emailHtml = `
        <div style="font-family:Arial,sans-serif;padding:32px;background:#FAF9F6;color:#0D1B2A;border-radius:12px;border:1px solid #E8E4DC;max-width:600px;margin:0 auto;">
          <div style="text-align:center;border-bottom:2px solid #C9A84C;padding-bottom:20px;margin-bottom:24px;">
            <h2 style="color:#0D1B2A;margin:0;font-size:26px;">Covenant Crest Group</h2>
            <p style="color:#7A8694;margin:4px 0 0;font-size:12px;letter-spacing:0.15em;text-transform:uppercase;">Interview Invitation</p>
          </div>
          <h3 style="color:#0D1B2A;font-size:18px;">Dear ${candidateName},</h3>
          <p style="font-size:14px;line-height:1.75;color:#4A5568;">Thank you for your application. We are pleased to invite you to a formal online video interview for the <strong>${jobTitle || 'recruitment'}</strong> position with Covenant Crest Group.</p>
          
          <div style="background:#fff;border:1px solid #E8E4DC;border-radius:8px;padding:20px;margin:24px 0;box-shadow:0 4px 12px rgba(13,27,42,0.02);">
            <div style="font-size:11px;font-weight:700;color:#C9A84C;text-transform:uppercase;margin-bottom:8px;letter-spacing:0.08em;">Interview Schedule</div>
            <div style="font-size:15px;font-weight:600;color:#0D1B2A;margin-bottom:12px;">📅 ${startDateTime.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })}</div>
            <div style="font-size:15px;font-weight:600;color:#0D1B2A;margin-bottom:16px;">🕒 ${startDateTime.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })} &mdash; ${endDateTime.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })} (London Time)</div>
            
            <a href="${mockTeamsLink}" style="display:inline-block;background:#0078D4;color:#fff;padding:12px 24px;border-radius:4px;font-weight:600;text-decoration:none;font-size:13px;text-align:center;box-shadow:0 3px 8px rgba(0,120,212,0.25);" target="_blank" rel="noopener">Join Microsoft Teams Meeting</a>
          </div>
          
          <p style="font-size:13px;line-height:1.75;color:#7A8694;">Please ensure you have a stable internet connection, working camera, and microphone. If you have any scheduling conflicts, please reply directly to this email or call <strong>07346 809846</strong> as soon as possible.</p>
          
          <div style="border-top:1px solid #E8E4DC;margin-top:28px;padding-top:16px;text-align:center;font-size:11px;color:#9AA5B4;">
            Covenant Crest Group Ltd &bull; Registered in England & Wales Co. No. 16528951 &bull; Built on Promise.
          </div>
        </div>
      `;

      await sendEmail({
        to: [candidateEmail, CFG.SUPER_ADMIN_EMAIL.toLowerCase()],
        subject: `Interview Scheduled: ${jobTitle || 'Covenant Crest Role'} — Covenant Crest Group`,
        html: emailHtml,
        from: 'recruitment@covenantcrest.co.uk'
      }).catch(e => console.error('[M365 Sandbox] Invite Email dispatch failed:', e.message));

      return res.json({
        success: true,
        mode: 'sandbox',
        message: 'Successfully booked Teams Interview (Diagnostics/Sandbox Mode). Invitation email sent to candidate.',
        joinUrl: mockTeamsLink,
        dateTime: startDateTime,
        candidateName
      });
    }

    // Live Microsoft Graph API Integration
    const accessToken = await getMicrosoftAccessToken();
    const eventBody = JSON.stringify({
      subject: `Interview: ${candidateName} for ${jobTitle || 'Covenant Crest Role'}`,
      body: {
        contentType: 'HTML',
        content: `Covenant Crest Portal Automated Interview Placement.<br><br><strong>Candidate Details:</strong><br>Name: ${candidateName}<br>Email: ${candidateEmail}<br>Job: ${jobTitle || 'General Placement'}<br><br>Please click the Teams link below to start the video interview.`
      },
      start: {
        dateTime: startDateTime.toISOString(),
        timeZone: 'GMT Standard Time'
      },
      end: {
        dateTime: endDateTime.toISOString(),
        timeZone: 'GMT Standard Time'
      },
      location: {
        displayName: 'Microsoft Teams Video Meeting'
      },
      attendees: [
        {
          emailAddress: {
            address: candidateEmail,
            name: candidateName
          },
          type: 'required'
        },
        {
          emailAddress: {
            address: CFG.SUPER_ADMIN_EMAIL.toLowerCase(),
            name: 'Jaby K'
          },
          type: 'required'
        }
      ],
      isOnlineMeeting: true,
      onlineMeetingProvider: 'teamsForBusiness'
    });

    const createResult = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'graph.microsoft.com',
        path: `/v1.0/users/${organiserEmail}/calendar/events`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(eventBody)
        }
      }, (res) => {
        let d = '';
        res.on('data', chunk => d += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            if (res.statusCode >= 400) {
              let errMsg = parsed.error?.message || 'Graph Calendar Error ' + res.statusCode;
              if (parsed.error?.code === 'Authorization_RequestDenied' || res.statusCode === 403) {
                errMsg = 'Permission Denied (403): Please ensure your Azure App Registration has been granted "Application Permissions" (not Delegated permissions) for "Calendars.ReadWrite" and "Mail.Send", and that you clicked "Grant admin consent" in the Azure portal.';
              }
              reject(new Error(errMsg));
            } else {
              resolve(parsed);
            }
          } catch(e) { reject(e); }
        });
      });
      req.on('error', reject);
      req.write(eventBody);
      req.end();
    });

    const teamsLink = createResult.onlineMeeting?.joinUrl || createResult.webLink;

    // Send the gorgeous M365-branded confirmation email via Graph API
    const emailBody = JSON.stringify({
      message: {
        subject: `Interview Scheduled: ${jobTitle || 'Covenant Crest Role'} — Covenant Crest Group`,
        body: {
          contentType: 'HTML',
          content: `
            <div style="font-family:Arial,sans-serif;padding:32px;background:#FAF9F6;color:#0D1B2A;border-radius:12px;border:1px solid #E8E4DC;max-width:600px;margin:0 auto;">
              <div style="text-align:center;border-bottom:2px solid #C9A84C;padding-bottom:20px;margin-bottom:24px;">
                <h2 style="color:#0D1B2A;margin:0;font-size:26px;">Covenant Crest Group</h2>
                <p style="color:#7A8694;margin:4px 0 0;font-size:12px;letter-spacing:0.15em;text-transform:uppercase;">Interview Invitation</p>
              </div>
              <h3 style="color:#0D1B2A;font-size:18px;">Dear ${candidateName},</h3>
              <p style="font-size:14px;line-height:1.75;color:#4A5568;">Thank you for your application. We are pleased to invite you to a formal online video interview for the <strong>${jobTitle || 'recruitment'}</strong> position with Covenant Crest Group.</p>
              
              <div style="background:#fff;border:1px solid #E8E4DC;border-radius:8px;padding:20px;margin:24px 0;box-shadow:0 4px 12px rgba(13,27,42,0.02);">
                <div style="font-size:11px;font-weight:700;color:#C9A84C;text-transform:uppercase;margin-bottom:8px;letter-spacing:0.08em;">Interview Schedule</div>
                <div style="font-size:15px;font-weight:600;color:#0D1B2A;margin-bottom:12px;">📅 ${startDateTime.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })}</div>
                <div style="font-size:15px;font-weight:600;color:#0D1B2A;margin-bottom:16px;">🕒 ${startDateTime.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })} &mdash; ${endDateTime.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })} (London Time)</div>
                
                <a href="${teamsLink}" style="display:inline-block;background:#0078D4;color:#fff;padding:12px 24px;border-radius:4px;font-weight:600;text-decoration:none;font-size:13px;text-align:center;box-shadow:0 3px 8px rgba(0,120,212,0.25);" target="_blank" rel="noopener">Join Microsoft Teams Meeting</a>
              </div>
              
              <p style="font-size:13px;line-height:1.75;color:#7A8694;">Please ensure you have a stable internet connection, working camera, and microphone. If you have any scheduling conflicts, please reply directly to this email or call <strong>07346 809846</strong> as soon as possible.</p>
              
              <div style="border-top:1px solid #E8E4DC;margin-top:28px;padding-top:16px;text-align:center;font-size:11px;color:#9AA5B4;">
                Covenant Crest Group Ltd &bull; Registered in England & Wales Co. No. 16528951 &bull; Built on Promise.
              </div>
            </div>
          `
        },
        toRecipients: [
          {
            emailAddress: {
              address: candidateEmail
            }
          }
        ]
      },
      saveToSentItems: "true"
    });

    await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'graph.microsoft.com',
        path: `/v1.0/users/${organiserEmail}/sendMail`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(emailBody)
        }
      }, (res) => {
        let d = '';
        res.on('data', chunk => d += chunk);
        res.on('end', () => {
          if (res.statusCode >= 400) {
            console.error('[M365 Graph] Invite Email dispatch failed:', res.statusCode, d);
            resolve({ success: false }); 
          } else {
            console.log('[M365 Graph] Successfully sent Teams invite email to:', candidateEmail);
            resolve({ success: true });
          }
        });
      });
      req.on('error', (e) => {
        console.error('[M365 Graph] Network error during invite email dispatch:', e.message);
        resolve({ success: false });
      });
      req.write(emailBody);
      req.end();
    });

    res.json({
      success: true,
      mode: 'live',
      message: 'Microsoft Teams Interview booked successfully on your Outlook Calendar and invitation email sent!',
      eventId: createResult.id,
      joinUrl: teamsLink,
      dateTime: startDateTime,
      candidateName
    });

  } catch (e) {
    console.error('[M365 Teams Integration Error]:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─────────────────────────────────────────────
// 404 + ERROR HANDLER
// ─────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Endpoint not found.' }));

app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error.' });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Covenant Crest Elite API v3.0 running on port ${PORT}`);
  console.log(`   Super Admin   : ${CFG.SUPER_ADMIN_EMAIL}`);
  console.log(`   Allowed Origin: ${CFG.ALLOWED_ORIGIN}`);
  console.log(`   CRM Engine    : ${CFG.HUBSPOT_ACCESS_TOKEN ? '✅ HubSpot API v3 CRM Active' : '⚠️  HUBSPOT_ACCESS_TOKEN not set'}`);
  console.log(`   Mail Engine   : ${CFG.RESEND_API_KEY ? '✅ Resend Outbound Service Active' : '⚠️  RESEND_API_KEY not set'}`);
  
  if (CFG.MICROSOFT_CLIENT_ID && CFG.MICROSOFT_TENANT_ID === 'common') {
    console.log('   Microsoft SSO : ⚠️  MICROSOFT_TENANT_ID is set to "common". Microsoft Graph calendar/Teams scheduling will not function. Please configure your specific Azure Directory (Tenant) ID.');
  } else if (CFG.MICROSOFT_CLIENT_ID) {
    console.log('   Microsoft SSO : ✅ Azure AD SSO Configured');
  } else {
    console.log('   Microsoft SSO : ⚠️  MICROSOFT_CLIENT_ID not set');
  }

  console.log(`   Cloudinary    : ${CFG.CLOUDINARY_KEY  ? '✅ Assets CDN Configured' : '⚠️  credentials not set'}`);
  console.log(`   Authenticator : ${CFG.SUPER_ADMIN_2FA_SECRET ? '✅ 2FA Authentication Enforced' : '⚠️  SUPER_ADMIN_2FA_SECRET not set (2FA inactive)'}`);
  console.log('\n📋 Active Premium Endpoints:');
  [
    'GET    /api/jobs                — public job listings',
    'POST   /api/auth/login          — traditional user login',
    'GET    /api/auth/me             — retrieve active session',
    'GET    /api/auth/2fa-setup      — retrieve admin 2FA QR code (auth)',
    'GET    /api/auth/microsoft-login — start secure Microsoft Admin SSO',
    'GET    /api/auth/microsoft-callback — secure Microsoft auth callback',
    'GET    /api/contacts            — view client inquiries (auth)',
    'POST   /api/contacts            — submit express booking wizard (public)',
    'GET    /api/applications        — view candidate compliance portal (auth)',
    'POST   /api/applications        — submit pre-vetted compliance registration (public)',
    'POST   /api/upload              — upload candidate CV/assets to Cloudinary (auth)',
    'GET    /api/users               — list admin users (super admin)',
    'POST   /api/users               — spawn employee credentials (super admin)',
    'POST   /api/netlify-webhook     — Netlify form webhook processor',
    'POST   /api/diagnostics/test-resend — dispatch Resend test email (super admin)',
    'POST   /api/diagnostics/test-hubspot — verify HubSpot CRM token sync (super admin)',
  ].forEach(e => console.log('   ' + e));
  console.log('');
});

module.exports = app;
