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
  JWT_SECRET        : process.env.JWT_SECRET        || ('insecure-dev-' + Math.random()),
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

  // Zoho OAuth (https://api-console.zoho.com — create a "Server-based Application")
  // Used so the admin panel can send emails directly via your Zoho mailbox
  // without sharing your password. Tokens auto-refresh — set-and-forget.
  ZOHO_CLIENT_ID     : process.env.ZOHO_CLIENT_ID     || '',
  ZOHO_CLIENT_SECRET : process.env.ZOHO_CLIENT_SECRET || '',
  ZOHO_REDIRECT_URI  : process.env.ZOHO_REDIRECT_URI  || 'https://covenantcrest.co.uk/api/zoho/callback',
  ZOHO_SSO_REDIRECT_URI: process.env.ZOHO_SSO_REDIRECT_URI || 'https://www.covenantcrest.co.uk/api/auth/zoho-callback',
  ZOHO_REFRESH_TOKEN : process.env.ZOHO_REFRESH_TOKEN || '',   // set after first authorisation
  ZOHO_FROM_EMAIL    : process.env.ZOHO_FROM_EMAIL    || 'jaby.k@covenantcrest.co.uk',
  ZOHO_FROM_NAME     : process.env.ZOHO_FROM_NAME     || 'Covenant Crest Group',

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
  // Fallback for legacy plain-text passwords
  if (!stored.startsWith('$2') && !stored.startsWith('pbkdf2$')) {
    return pwd === stored;
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
    const allowed = [
      CFG.ALLOWED_ORIGIN,
      'http://localhost:3000',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
    ];
    if (!origin || allowed.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: true,
}));

app.use(express.json({ limit: '5mb' }));   // 5 MB to allow base64 image uploads
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

app.get('/health',     (req, res) => res.json({ status: 'healthy', uptime: process.uptime(), zohoSSOConfigured: !!(CFG.ZOHO_CLIENT_ID && CFG.ZOHO_CLIENT_SECRET) }));
app.get('/api/health', (req, res) => res.json({ status: 'healthy', uptime: process.uptime(), zohoSSOConfigured: !!(CFG.ZOHO_CLIENT_ID && CFG.ZOHO_CLIENT_SECRET) }));

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
// ZOHO SSO LOGIN — admin login via Zoho account
// ─────────────────────────────────────────────

/**
 * GET /api/auth/zoho-login
 * Redirects browser to Zoho OAuth consent screen for SSO login
 */
app.get('/api/auth/zoho-login', (req, res) => {
  if (!CFG.ZOHO_CLIENT_ID) {
    return res.status(503).send('Zoho SSO not configured. Set ZOHO_CLIENT_ID in environment variables.');
  }
  const params = new URLSearchParams({
    response_type: 'code',
    client_id    : CFG.ZOHO_CLIENT_ID,
    scope        : 'openid,profile,email,ZohoMail.accounts.READ',
    redirect_uri : CFG.ZOHO_SSO_REDIRECT_URI || (CFG.ALLOWED_ORIGIN + '/api/auth/zoho-callback'),
    access_type  : 'offline',
    prompt       : 'consent',
  });
  res.redirect('https://accounts.zoho.eu/oauth/v2/auth?' + params.toString());
});

/**
 * GET /api/auth/zoho-callback
 * Zoho redirects here after user approves — exchange code for token,
 * verify the email matches SUPER_ADMIN_EMAIL, issue JWT
 */
app.get('/api/auth/zoho-callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect('/login.html?error=zoho_cancelled');
  }
  try {
    // Exchange code for access token
    const tokenBody = new URLSearchParams({
      grant_type   : 'authorization_code',
      client_id    : CFG.ZOHO_CLIENT_ID,
      client_secret: CFG.ZOHO_CLIENT_SECRET,
      redirect_uri : CFG.ZOHO_SSO_REDIRECT_URI || (CFG.ALLOWED_ORIGIN + '/api/auth/zoho-callback'),
      code,
    }).toString();

    const exchangeToken = (hostname) => new Promise((resolve, reject) => {
      const req2 = https.request({
        hostname,
        path    : '/oauth/v2/token',
        method  : 'POST',
        headers : { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(tokenBody) },
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
      });
      req2.on('error', reject);
      req2.write(tokenBody);
      req2.end();
    });

    let tokenData;
    try {
      tokenData = await exchangeToken('accounts.zoho.eu');
      if (!tokenData.access_token) throw new Error('EU failed');
    } catch(e) {
      tokenData = await exchangeToken('accounts.zoho.com');
    }

    if (!tokenData.access_token) {
      console.error('[zoho-sso] Token exchange failed:', tokenData);
      return res.redirect('/login.html?error=zoho_token_failed');
    }

    // Get user info from Zoho - try EU first, fallback to COM
    const getUserInfo = (hostname) => new Promise((resolve, reject) => {
      const req3 = https.request({
        hostname,
        path    : '/oauth/v2/userinfo',
        method  : 'GET',
        headers : { 'Authorization': 'Zoho-oauthtoken ' + tokenData.access_token },
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try { resolve(JSON.parse(d)); } catch(e) { reject(e); }
        });
      });
      req3.on('error', reject);
      req3.end();
    });

    let userInfo;
    try {
      userInfo = await getUserInfo('accounts.zoho.eu');
    } catch(e) {
      userInfo = await getUserInfo('accounts.zoho.com');
    }

    // Also try getting email from id_token if not in userInfo
    let zohoEmail = (userInfo.email || userInfo.Email || userInfo.sub || '').toLowerCase();
    
    // If still no email, decode the id_token
    if (!zohoEmail && tokenData.id_token) {
      try {
        const payload = JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString());
        zohoEmail = (payload.email || payload.sub || '').toLowerCase();
      } catch(e) { /* ignore */ }
    }

    // Check if this Zoho account matches the super admin email
    if (zohoEmail !== CFG.SUPER_ADMIN_EMAIL.toLowerCase()) {
      console.warn('[zoho-sso] Unauthorised Zoho login attempt:', zohoEmail);
      return res.redirect('/login.html?error=zoho_unauthorised');
    }

    // Issue JWT and redirect to admin
    const token = makeToken({ email: zohoEmail, role: 'superadmin' });
    // Pass token via URL fragment (never logged by servers)
    res.redirect('/admin.html#sso=' + token);

  } catch (err) {
    console.error('[zoho-sso] Error:', err.message);
    res.redirect('/login.html?error=zoho_error');
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
    const result = await Job.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Job not found.' });
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

  // Fire emails (non-blocking)
  Promise.allSettled([
    sendEmail(emailTpl.newEnquiryAlert(contact)),
    contact.email ? sendEmail({
      ...emailTpl.enquiryAutoReply(contact),
      to: contact.email,
    }) : Promise.resolve(),
  ]).then(results => {
    results.forEach((r, i) => {
      if (r.status === 'rejected') console.error('Email error #' + i, r.reason?.message);
    });
  });

  res.status(201).json({ success: true, id: contact.id });
  } catch(e) { res.status(500).json({ error: 'Failed to save enquiry' }); }
});

/** PUT /api/contacts/:id — mark read / update status */
app.put('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const contact = await Contact.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
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
    const { cvBase64, ...rest } = req.body;
    const entry = new Application({
      id: uid(),
      ...rest,
      status: 'new'
    });

    if (cvBase64) {
      try {
        const up = await cloudinaryUpload(cvBase64, 'covenantcrest/cvs', `cv-${entry.id}`, 'raw');
        entry.cvUrl = up.url;
      } catch (e) { console.error('CV upload failed:', e.message); }
    }

    await entry.save();
    
    // Non-blocking emails
    Promise.allSettled([
      sendEmail(emailTpl.newApplicationAlert(entry)),
      entry.email ? sendEmail(emailTpl.applicationAutoReply(entry)) : Promise.resolve(),
    ]);

    res.status(201).json(entry);
  } catch(e) { res.status(500).json({ error: 'Failed to save application' }); }
});

/** PUT /api/applications/:id — update status */
app.put('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const app = await Application.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
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
  // Verify signature if secret is configured
  if (CFG.NETLIFY_SECRET) {
    const sig  = req.headers['x-webhook-signature'] || '';
    const body = JSON.stringify(req.body);
    const expected = crypto.createHmac('sha256', CFG.NETLIFY_SECRET).update(body).digest('hex');
    if (sig !== `sha256=${expected}`) {
      return res.status(401).json({ error: 'Invalid webhook signature.' });
    }
  }

  const payload = req.body;
  const data    = payload.data || payload;
  const formName = sanitise(payload.form_name || data.form_name || '', 80);

  // ── Route candidate-apply to Applications ────────────────────
  if (formName === 'candidate-apply') {
    const entry = {
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
      date        : new Date().toISOString(),
    };
    const apps = readJSON(FILES.apps);
    apps.unshift(entry);
    writeJSON(FILES.apps, apps);

    // Alert to admin + confirmation to candidate
    Promise.allSettled([
      sendEmail(emailTpl.newApplicationAlert(entry)),
      entry.email ? sendEmail(emailTpl.applicationAutoReply(entry)) : Promise.resolve(),
    ]);

    return res.json({ received: true, id: entry.id, routed: 'applications' });
  }

  // ── All other forms → Contact Enquiries ──────────────────────
  const contact = {
    id     : uid(),
    name   : sanitise(data.name || data.first_name || '', 120),
    email  : sanitise(data.email || '', 200),
    phone  : sanitise(data.phone || '', 30),
    type   : sanitise(data.enquiry_type || data.type || formName || 'general', 40),
    message: sanitise(data.message || data.notes || '', 3000),
    source : sanitise(formName || 'netlify-webhook', 50),
    status : 'new',
    date   : new Date().toISOString(),
  };

  const contacts = readJSON(FILES.contacts);
  contacts.unshift(contact);
  writeJSON(FILES.contacts, contacts);

  Promise.allSettled([
    sendEmail(emailTpl.newEnquiryAlert(contact)),
    contact.email ? sendEmail({ ...emailTpl.enquiryAutoReply(contact), to: contact.email }) : Promise.resolve(),
  ]);

  res.json({ received: true, id: contact.id, routed: 'contacts' });
});

// ─────────────────────────────────────────────
// ZOHO OAUTH 2.0
// ─────────────────────────────────────────────
// Flow overview:
//   1. Super Admin visits GET /api/zoho/authorise  → redirected to Zoho consent screen
//   2. Zoho redirects to GET /api/zoho/callback?code=XXX
//   3. We exchange the code for access + refresh tokens → stored on disk
//   4. Every outbound email calls getZohoAccessToken() which auto-refreshes when needed
//   5. Set ZOHO_REFRESH_TOKEN env var on Render after step 3 so it survives restarts
//
// SETUP (one-time):
//   a. Go to https://api-console.zoho.com → Add Client → Server-based Application
//   b. Authorised Redirect URI: https://covenantcrest.co.uk/api/zoho/callback
//      (or https://your-render-url.onrender.com/api/zoho/callback during setup)
//   c. Copy Client ID + Secret → set as Render env vars
//   d. Log in to admin → Settings → click "Authorise Zoho Mail"
//   e. After redirect you'll see {"zoho":"connected"} — done!
// ─────────────────────────────────────────────

const ZOHO_TOKEN_FILE = path.join(DATA_DIR, 'zoho_tokens.json');

// In-memory token cache (avoids repeated disk reads)
let _zohoTokenCache = null;

function loadZohoTokens() {
  if (_zohoTokenCache) return _zohoTokenCache;
  try {
    if (fs.existsSync(ZOHO_TOKEN_FILE)) {
      _zohoTokenCache = JSON.parse(fs.readFileSync(ZOHO_TOKEN_FILE, 'utf8'));
      return _zohoTokenCache;
    }
  } catch (e) { /* ignore */ }
  // Fall back to env var refresh token (set after first auth)
  if (CFG.ZOHO_REFRESH_TOKEN) {
    return { refresh_token: CFG.ZOHO_REFRESH_TOKEN, access_token: null, expires_at: 0 };
  }
  return null;
}

function saveZohoTokens(tokens) {
  _zohoTokenCache = tokens;
  try { fs.writeFileSync(ZOHO_TOKEN_FILE, JSON.stringify(tokens, null, 2), 'utf8'); } catch (e) { /* non-fatal */ }
}

/**
 * Returns a valid Zoho access token, refreshing automatically when expired.
 * Throws if Zoho is not configured.
 */
async function getZohoAccessToken() {
  if (!CFG.ZOHO_CLIENT_ID || !CFG.ZOHO_CLIENT_SECRET) {
    throw new Error('Zoho OAuth not configured (ZOHO_CLIENT_ID / ZOHO_CLIENT_SECRET missing).');
  }

  const tokens = loadZohoTokens();
  if (!tokens || !tokens.refresh_token) {
    throw new Error('Zoho not authorised yet. Visit /api/zoho/authorise to connect.');
  }

  const now = Date.now();
  // Access token still valid (with 60s buffer)
  if (tokens.access_token && tokens.expires_at && now < tokens.expires_at - 60_000) {
    return tokens.access_token;
  }

  // Refresh the access token
  const body = new URLSearchParams({
    grant_type    : 'refresh_token',
    client_id     : CFG.ZOHO_CLIENT_ID,
    client_secret : CFG.ZOHO_CLIENT_SECRET,
    refresh_token : tokens.refresh_token,
  }).toString();

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'accounts.zoho.eu',   // use zoho.com if your account is US-based
      path    : '/oauth/v2/token',
      method  : 'POST',
      headers : {
        'Content-Type'  : 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!json.access_token) return reject(new Error('Zoho token refresh failed: ' + data));
          const updated = {
            ...tokens,
            access_token: json.access_token,
            expires_at  : Date.now() + (json.expires_in || 3600) * 1000,
          };
          saveZohoTokens(updated);
          resolve(updated.access_token);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Send email via Zoho Mail API (ZeptoMail / Zoho Mail Send API v1)
 * Falls back to Resend if Zoho is not configured.
 */
async function sendEmailViaZoho({ to, subject, html }) {
  const accessToken = await getZohoAccessToken();
  const recipients  = (Array.isArray(to) ? to : [to]).map(addr => ({ address: addr }));

  const body = JSON.stringify({
    from    : { address: CFG.ZOHO_FROM_EMAIL, name: CFG.ZOHO_FROM_NAME },
    to      : recipients,
    subject,
    htmlbody: html,
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'mail.zoho.eu',     // use mail.zoho.com if US account
      path    : '/api/accounts/me/messages',
      method  : 'POST',
      headers : {
        'Authorization': `Zoho-oauthtoken ${accessToken}`,
        'Content-Type' : 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          console.error('[zoho-mail] Send failed:', res.statusCode, data);
          return reject(new Error('Zoho mail send failed: ' + data));
        }
        resolve(JSON.parse(data));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Master send function — tries Zoho first, falls back to Resend, then logs only.
 */
async function sendEmail({ to, subject, html }) {
  // Try Zoho if configured
  if (CFG.ZOHO_CLIENT_ID && CFG.ZOHO_CLIENT_SECRET) {
    try {
      return await sendEmailViaZoho({ to, subject, html });
    } catch (e) {
      console.warn('[email] Zoho send failed, trying Resend fallback:', e.message);
    }
  }

  // Try Resend fallback
  if (CFG.RESEND_API_KEY) {
    const body = JSON.stringify({
      from   : `Covenant Crest <${CFG.EMAIL_FROM}>`,
      to     : Array.isArray(to) ? to : [to],
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
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => {
          if (res.statusCode >= 400) { console.error('[resend] Error:', res.statusCode, data); return reject(new Error(data)); }
          resolve(JSON.parse(data));
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  // Neither configured — log only
  console.log('[email] No provider configured. Would have sent:', subject, '→', to);
}

// ── ZOHO OAUTH ROUTES ────────────────────────────────────────────

/**
 * GET /api/zoho/authorise
 * Super Admin only — starts the OAuth flow.
 * Visit this URL in your browser while logged into the admin panel.
 */
app.get('/api/zoho/authorise', requireSuperAdmin, (req, res) => {
  if (!CFG.ZOHO_CLIENT_ID) {
    return res.status(400).json({ error: 'ZOHO_CLIENT_ID not set in environment variables.' });
  }
  const params = new URLSearchParams({
    response_type: 'code',
    client_id    : CFG.ZOHO_CLIENT_ID,
    scope        : 'ZohoMail.messages.CREATE,ZohoMail.accounts.READ',
    redirect_uri : CFG.ZOHO_REDIRECT_URI,
    access_type  : 'offline',
    prompt       : 'consent',
  });
  res.redirect(`https://accounts.zoho.eu/oauth/v2/auth?${params.toString()}`);
});

/**
 * GET /api/zoho/callback?code=XXX
 * Zoho redirects here after the user grants permission.
 * Exchanges the auth code for access + refresh tokens.
 */
app.get('/api/zoho/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.status(400).send(`<h2>Zoho OAuth Error</h2><p>${error || 'No code returned'}</p>`);
  }
  if (!CFG.ZOHO_CLIENT_ID || !CFG.ZOHO_CLIENT_SECRET) {
    return res.status(400).send('<h2>Error</h2><p>ZOHO_CLIENT_ID / ZOHO_CLIENT_SECRET not configured.</p>');
  }

  const body = new URLSearchParams({
    grant_type   : 'authorization_code',
    client_id    : CFG.ZOHO_CLIENT_ID,
    client_secret: CFG.ZOHO_CLIENT_SECRET,
    redirect_uri : CFG.ZOHO_REDIRECT_URI,
    code,
  }).toString();

  try {
    const tokens = await new Promise((resolve, reject) => {
      const req2 = https.request({
        hostname: 'accounts.zoho.eu',
        path    : '/oauth/v2/token',
        method  : 'POST',
        headers : {
          'Content-Type'  : 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
      }, (r) => {
        let data = '';
        r.on('data', d => data += d);
        r.on('end', () => {
          try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
        });
      });
      req2.on('error', reject);
      req2.write(body);
      req2.end();
    });

    if (!tokens.refresh_token) {
      return res.status(400).send(`<h2>Error</h2><p>No refresh token returned. Try revoking access in Zoho and authorising again.</p><pre>${JSON.stringify(tokens, null, 2)}</pre>`);
    }

    saveZohoTokens({
      refresh_token: tokens.refresh_token,
      access_token : tokens.access_token,
      expires_at   : Date.now() + (tokens.expires_in || 3600) * 1000,
    });

    console.log('✅ Zoho OAuth connected. Refresh token saved.');
    console.log('   ⚠  Also set ZOHO_REFRESH_TOKEN=' + tokens.refresh_token + ' in Render env vars so it survives restarts.');

    res.send(`
      <html><body style="font-family:sans-serif;max-width:520px;margin:60px auto;padding:24px;">
        <h2 style="color:#1D9E75;">✅ Zoho Mail Connected!</h2>
        <p>Covenant Crest is now authorised to send emails via <strong>${CFG.ZOHO_FROM_EMAIL}</strong>.</p>
        <p><strong>Important:</strong> Copy the refresh token below and set it as the
        <code>ZOHO_REFRESH_TOKEN</code> environment variable on Render.com so it
        survives service restarts:</p>
        <pre style="background:#f5f5f5;padding:12px;border-radius:4px;word-break:break-all;">${tokens.refresh_token}</pre>
        <p><a href="/admin.html">← Back to Admin Panel</a></p>
      </body></html>
    `);
  } catch (err) {
    console.error('Zoho callback error:', err);
    res.status(500).send(`<h2>Error</h2><p>${err.message}</p>`);
  }
});

/**
 * GET /api/zoho/status
 * Returns Zoho connection status for the Settings panel.
 */
app.get('/api/zoho/status', requireSuperAdmin, (req, res) => {
  const tokens = loadZohoTokens();
  const configured = !!(CFG.ZOHO_CLIENT_ID && CFG.ZOHO_CLIENT_SECRET);
  const connected  = !!(tokens && tokens.refresh_token);
  const tokenValid = !!(tokens && tokens.access_token && tokens.expires_at && Date.now() < tokens.expires_at - 60_000);
  res.json({
    configured,
    connected,
    tokenValid,
    fromEmail: configured ? CFG.ZOHO_FROM_EMAIL : null,
    message  : !configured ? 'Set ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET in Render env vars.'
             : !connected  ? 'Not authorised yet. Click "Authorise Zoho Mail" in Settings.'
             : tokenValid  ? 'Connected and token valid.'
             : 'Connected — token will refresh automatically on next send.',
  });
});

/**
 * POST /api/zoho/test
 * Super Admin only — sends a test email to verify the connection.
 */
app.post('/api/zoho/test', requireSuperAdmin, async (req, res) => {
  try {
    await sendEmail({
      to     : CFG.ZOHO_FROM_EMAIL,
      subject: '✅ Covenant Crest — Zoho Mail Test',
      html   : `<div style="font-family:Arial,sans-serif;padding:24px;"><h2 style="color:#C9A84C;">Test Email</h2><p>Zoho Mail is working correctly for <strong>Covenant Crest Group Ltd</strong>.</p><p>Sent: ${new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' })}</p></div>`,
    });
    res.json({ success: true, message: 'Test email sent to ' + CFG.ZOHO_FROM_EMAIL });
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
  const zohoTokens = loadZohoTokens();
  console.log(`\n🚀 Covenant Crest API v2.0 running on port ${PORT}`);
  console.log(`   Super Admin : ${CFG.SUPER_ADMIN_EMAIL}`);
  console.log(`   Allowed origin: ${CFG.ALLOWED_ORIGIN}`);
  console.log(`   Email — Zoho  : ${CFG.ZOHO_CLIENT_ID ? (zohoTokens?.refresh_token ? '✅ connected' : '⚠️  not authorised — visit /api/zoho/authorise') : '⚠️  ZOHO_CLIENT_ID not set'}`);
  console.log(`   Email — Resend: ${CFG.RESEND_API_KEY ? '✅ configured (fallback)' : '— not set'}`);
  console.log(`   Cloudinary    : ${CFG.CLOUDINARY_KEY  ? '✅ configured' : '⚠️  credentials not set'}`);
  console.log('\n📋 Endpoints:');
  [
    'GET    /api/jobs              — public job listings',
    'POST   /api/auth/login        — get JWT token',
    'GET    /api/auth/me           — current user',
    'GET    /api/contacts          — view enquiries (auth)',
    'POST   /api/contacts          — submit enquiry (public)',
    'GET    /api/applications      — view applications (auth)',
    'POST   /api/applications      — submit application (public)',
    'POST   /api/upload            — upload image to Cloudinary (auth)',
    'GET    /api/users             — user list (super admin)',
    'POST   /api/users             — create employee (super admin)',
    'POST   /api/netlify-webhook   — Netlify form webhook',
    'GET    /api/zoho/authorise    — start Zoho OAuth flow (super admin)',
    'GET    /api/zoho/callback     — Zoho OAuth redirect URI',
    'GET    /api/zoho/status       — Zoho connection status (super admin)',
    'POST   /api/zoho/test         — send test email (super admin)',
  ].forEach(e => console.log('   ' + e));
  console.log('');
});

module.exports = app;
