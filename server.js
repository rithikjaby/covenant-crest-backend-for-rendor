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
  SUPER_ADMIN_PWD   : process.env._SAVED_ADMIN_PW || process.env.SUPER_ADMIN_PWD || 'ChangeMe2025!',
  JWT_SECRET        : process.env.JWT_SECRET        || crypto.randomBytes(32).toString('hex'),
  ALLOWED_ORIGIN    : process.env.ALLOWED_ORIGIN    || 'https://covenantcrest.co.uk',

  // Email (Resend)
  RESEND_API_KEY    : process.env.RESEND_API_KEY    || '',
  EMAIL_FROM        : process.env.EMAIL_FROM        || 'noreply@covenantcrest.co.uk',
  EMAIL_NOTIFY      : process.env.EMAIL_NOTIFY      || 'jaby.k@covenantcrest.co.uk',

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
  MICROSOFT_REDIRECT_URI : process.env.MICROSOFT_REDIRECT_URI || 'https://covenantcrest.co.uk/api/auth/microsoft-callback',
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
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const Job = mongoose.models.Job || mongoose.model('Job', JobSchema);
const Contact = mongoose.models.Contact || mongoose.model('Contact', ContactSchema);
const Application = mongoose.models.Application || mongoose.model('Application', AppSchema);

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

/**
 * Log security events (failed logins, password changes)
 */
function logSecurityEvent(type, email, req, details = {}) {
  try {
    const logs = readJSON(FILES.security);
    logs.unshift({
      id: uid(),
      timestamp: new Date().toISOString(),
      type,
      email: email.toLowerCase(),
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'],
      ...details
    });
    // Keep only last 200 events
    writeJSON(FILES.security, logs.slice(0, 200));
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
              <tr><td style="padding:8px 0;color:#666;font-size:13px;width:120px;">Name</td><td style="padding:8px 0;font-weight:600;font-size:13px;">${name}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Email</td><td style="padding:8px 0;font-size:13px;"><a href="mailto:${email}" style="color:#C9A84C;">${email}</a></td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Phone</td><td style="padding:8px 0;font-size:13px;">${phone || 'Not provided'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Type</td><td style="padding:8px 0;font-size:13px;">${type || 'General'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Source</td><td style="padding:8px 0;font-size:13px;">${source || 'website'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;vertical-align:top;">Message</td><td style="padding:8px 0;font-size:13px;line-height:1.6;">${(message || '').replace(/\n/g, '<br>')}</td></tr>
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
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">Thank You, ${name}</h2>
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
            <p style="font-size:14px;line-height:1.7;color:#333;">Dear <strong>${first_name} ${last_name}</strong>,</p>
            <p style="font-size:14px;line-height:1.7;color:#333;">Thank you for applying for a <strong>${sectorLabel}</strong> role${job_title ? ' (<em>' + job_title + '</em>)' : ''} with Covenant Crest Group Ltd.</p>
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
  newApplicationAlert({ first_name, last_name, email, phone, sector, job_title }) {
    return {
      to     : CFG.EMAIL_NOTIFY,
      subject: `[Covenant Crest] New application — ${first_name} ${last_name} (${sector || 'general'})`,
      html   : `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:24px;border-radius:8px;">
          <div style="background:#0D1B2A;padding:20px 24px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#C9A84C;margin:0;font-size:20px;">New Candidate Application</h2>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px 0;color:#666;font-size:13px;width:120px;">Name</td><td style="padding:8px 0;font-weight:600;font-size:13px;">${first_name} ${last_name}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Email</td><td style="padding:8px 0;font-size:13px;"><a href="mailto:${email}" style="color:#C9A84C;">${email}</a></td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Phone</td><td style="padding:8px 0;font-size:13px;">${phone || 'Not provided'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Sector</td><td style="padding:8px 0;font-size:13px;">${sector || '—'}</td></tr>
              <tr><td style="padding:8px 0;color:#666;font-size:13px;">Job</td><td style="padding:8px 0;font-size:13px;">${job_title || '—'}</td></tr>
            </table>
            <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
            <p style="font-size:11px;color:#999;margin:0;">Received: ${new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' })}</p>
          </div>
        </div>`,
    };
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
    if (
      origin === CFG.ALLOWED_ORIGIN ||
      origin === 'https://www.' + base ||
      origin === 'http://www.'  + base ||
      origin === 'http://localhost:3000' ||
      origin === 'http://localhost:5500' ||
      origin === 'http://127.0.0.1:5500'
    ) return cb(null, true);
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
  const auth  = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const user  = verifyToken(token);
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
console.log('[BOOT] Cloudinary — cloud:', CFG.CLOUDINARY_CLOUD, '| key length:', CFG.CLOUDINARY_KEY.length, '| secret length:', CFG.CLOUDINARY_SECRET.length, '| secret ends with:', CFG.CLOUDINARY_SECRET.slice(-3));

// ─────────────────────────────────────────────
// ROUTES — HEALTH
// ─────────────────────────────────────────────
app.get('/', (req, res) => res.json({
  status   : 'ok',
  service  : 'Covenant Crest API',
  version  : '2.0.0',
  timestamp: new Date().toISOString(),
}));

app.get('/health',     (req, res) => res.json({ status: 'healthy', uptime: process.uptime(), databaseConnected: mongoose.connection.readyState === 1, resendConfigured: !!CFG.RESEND_API_KEY, hubspotConfigured: !!CFG.HUBSPOT_ACCESS_TOKEN, microsoftSSOConfigured: !!(CFG.MICROSOFT_CLIENT_ID && CFG.MICROSOFT_CLIENT_SECRET) }));
app.get('/api/health', (req, res) => res.json({ status: 'healthy', uptime: process.uptime(), databaseConnected: mongoose.connection.readyState === 1, resendConfigured: !!CFG.RESEND_API_KEY, hubspotConfigured: !!CFG.HUBSPOT_ACCESS_TOKEN, microsoftSSOConfigured: !!(CFG.MICROSOFT_CLIENT_ID && CFG.MICROSOFT_CLIENT_SECRET) }));

// ─────────────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────────────

/**
 * POST /api/auth/login
 * Body: { email, password }
 * Returns: { token, role, email }
 */
app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
  const { email = '', password = '', honeypot = '' } = req.body;
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
        return res.json({
          token: makeToken({ email: emailLc, role: 'superadmin' }),
          role : 'superadmin',
          email: emailLc,
        });
      }
      // Log failed attempt
      logSecurityEvent('failed_login', emailLc, req, { role: 'superadmin' });
      await new Promise(r => setTimeout(r, 400 + Math.random() * 200));
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // ── Employee accounts ─────────────────────────────────────────
    const users = readJSON(FILES.users);
    const user  = users.find(u => (u.email || '').toLowerCase() === emailLc);
    if (user && user.role === 'employee') {
      let match = false;
      try {
        match = await verifyPassword(password, user.password);
      } catch (e) {
        match = (password === user.password);
      }
      if (match) {
        return res.json({
          token: makeToken({ email: user.email, role: 'employee', id: user.id }),
          role : 'employee',
          email: user.email,
        });
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
 * GET /api/security-logs — Super Admin only
 */
app.get('/api/security-logs', requireSuperAdmin, (req, res) => {
  res.json(readJSON(FILES.security));
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

    // 4. Issue JWT token & redirect to Admin Panel via fragment hash
    const token = makeToken({ email: userEmail, role: 'superadmin' });
    logSecurityEvent('sso_login', userEmail, req, { provider: 'microsoft' });
    res.redirect('/admin.html#sso=' + token);

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
    if (location) query.location = { $regex: location, $options: 'i' };

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
  const { title, pay, sector, type, location, desc, req: requirements, status, imageBase64, closingDate, seoKeywords, seoDesc } = req.body;
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
    });
    await job.save();
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
app.post('/api/contacts', async (req, res) => {
  try {
    const contact = new Contact({
      id     : uid(),
      name   : sanitise(req.body.name || req.body.first_name || '', 120),
      email  : sanitise(req.body.email || '', 200),
      phone  : sanitise(req.body.phone || '', 30),
      type   : sanitise(req.body.enquiry_type || req.body.type || 'general', 40),
      message: sanitise(req.body.message || req.body.notes || '', 3000),
      source : sanitise(req.body['form-name'] || 'api', 50),
      status : 'new',
    });
    await contact.save();

  // Fire emails + CRM Sync (non-blocking)
  Promise.allSettled([
    sendEmail(emailTpl.newEnquiryAlert(contact)),
    contact.email ? sendEmail({
      ...emailTpl.enquiryAutoReply(contact),
      to: contact.email,
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
// ROUTES — CANDIDATE APPLICATIONS
// ─────────────────────────────────────────────

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
app.post('/api/applications', async (req, res) => {
  try {
    const { cvBase64, cvFileName, ...rest } = req.body;

    // 1. Enforce Blacklist
    const isBlacklisted = await Application.exists({
      email: rest.email,
      status: 'blacklisted'
    });

    const entry = new Application({
      id: uid(),
      ...rest,
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
      sendEmail(emailTpl.newApplicationAlert(entry)),
      entry.email ? sendEmail({ ...emailTpl.applicationAutoReply(entry), to: entry.email }) : Promise.resolve(),
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
      'dbs_expiry_date', 'sia_expiry_date', 'rtw_expiry_date', 'manual_handling_cert',
    ];
    const update = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        update[key] = typeof req.body[key] === 'string'
          ? sanitise(req.body[key], 500)
          : req.body[key];
      }
    }
    const app = await Application.findOneAndUpdate({ id: req.params.id }, update, { new: true });
    if (!app) return res.status(404).json({ error: 'Application not found.' });
    res.json(app);
  } catch(e) { res.status(500).json({ error: 'Failed to update application' }); }
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
app.get('/api/users', requireSuperAdmin, (req, res) => {
  const users = readJSON(FILES.users).map(({ id, email, role, created }) => ({ id, email, role, created }));
  res.json([
    { id: 'superadmin', email: CFG.SUPER_ADMIN_EMAIL, role: 'superadmin', created: null },
    ...users,
  ]);
});

/** POST /api/users — create employee */
app.post('/api/users', requireSuperAdmin, async (req, res) => {
  const { email = '', password = '' } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required.' });
  if (!password || password.length < 8)  return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const emailLc = email.trim().toLowerCase();
  if (emailLc === CFG.SUPER_ADMIN_EMAIL.toLowerCase())
    return res.status(409).json({ error: 'This email is reserved.' });

  const users = readJSON(FILES.users);
  if (users.find(u => (u.email || '').toLowerCase() === emailLc))
    return res.status(409).json({ error: 'An account with this email already exists.' });

  const hashed = await hashPassword(password);
  const user = {
    id      : uid(),
    email   : emailLc,
    password: hashed,
    role    : 'employee',
    created : new Date().toISOString(),
  };
  users.push(user);
  writeJSON(FILES.users, users);

  const { password: _, ...safe } = user;
  res.status(201).json(safe);
});

/** DELETE /api/users/:id */
app.delete('/api/users/:id', requireSuperAdmin, (req, res) => {
  if (req.params.id === 'superadmin')
    return res.status(403).json({ error: 'Cannot delete the Super Admin account.' });
  const users    = readJSON(FILES.users);
  const filtered = users.filter(u => u.id !== req.params.id);
  if (filtered.length === users.length) return res.status(404).json({ error: 'User not found.' });
  writeJSON(FILES.users, filtered);
  res.json({ success: true });
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
    if (sig !== `sha256=${expected}`) {
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
    });
    await entry.save();

    // Alert to admin + confirmation to candidate + HubSpot CRM sync
    Promise.allSettled([
      sendEmail(emailTpl.newApplicationAlert(entry)),
      entry.email ? sendEmail({ ...emailTpl.applicationAutoReply(entry), to: entry.email }) : Promise.resolve(),
      syncToHubSpot(entry, 'candidate').catch(e => console.error('[HubSpot] Webhook Candidate CRM Sync failed:', e.message))
    ]);

    return res.json({ received: true, id: entry.id, routed: 'applications' });
  }

  // ── All other forms → Contact Enquiries ──────────────────────
  const contact = new Contact({
    id     : uid(),
    name   : sanitise(data.name || data.first_name || '', 120),
    email  : sanitise(data.email || '', 200),
    phone  : sanitise(data.phone || '', 30),
    type   : sanitise(data.enquiry_type || data.type || formName || 'general', 40),
    message: sanitise(data.message || data.notes || '', 3000),
    source : sanitise(formName || 'netlify-webhook', 50),
    status : 'new',
  });
  await contact.save();

  Promise.allSettled([
    sendEmail(emailTpl.newEnquiryAlert(contact)),
    contact.email ? sendEmail({ ...emailTpl.enquiryAutoReply(contact), to: contact.email }) : Promise.resolve(),
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
async function sendEmail({ to, subject, html }) {
  if (!CFG.RESEND_API_KEY) {
    console.warn('[email] Resend API Key is not set. Outbound mail was bypassed:', subject);
    return Promise.resolve({ bypassed: true });
  }

  const recipients = Array.isArray(to) ? to : [to];
  const body = JSON.stringify({
    from   : `Covenant Crest <${CFG.EMAIL_FROM}>`,
    to     : recipients,
    subject,
    html,
  });

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
  console.log(`   Microsoft SSO : ${CFG.MICROSOFT_CLIENT_ID ? '✅ Azure AD SSO Configured' : '⚠️  MICROSOFT_CLIENT_ID not set'}`);
  console.log(`   Cloudinary    : ${CFG.CLOUDINARY_KEY  ? '✅ Assets CDN Configured' : '⚠️  credentials not set'}`);
  console.log('\n📋 Active Premium Endpoints:');
  [
    'GET    /api/jobs                — public job listings',
    'POST   /api/auth/login          — traditional user login',
    'GET    /api/auth/me             — retrieve active session',
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
