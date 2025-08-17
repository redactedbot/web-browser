// index.js -- full server with Puppeteer + Readability + Redis + JWT + SSRF protections

'use strict';
const express = require('express');
const bodyParser = require('body-parser');
const puppeteer = require('puppeteer');
const Redis = require('ioredis');
const NodeCache = require('node-cache'); // small in-memory fallback
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');
const jwt = require('jsonwebtoken');
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || null;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-change-me';
const API_KEY_TTL = parseInt(process.env.API_KEY_TTL || '0', 10);
const JWT_TTL = parseInt(process.env.JWT_TTL_SECONDS || '900', 10);
const CACHE_TTL = parseInt(process.env.CACHE_TTL_SECONDS || '300', 10);
const RATE_LIMIT_PER_MIN = parseInt(process.env.RATE_LIMIT_PER_MIN || '60', 10);

const app = express();
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));

// Redis (preferred); fallback to in-memory NodeCache for dev
let redis;
if (REDIS_URL) {
  redis = new Redis(REDIS_URL);
} else {
  console.warn('No REDIS_URL provided — using in-memory cache (not for production).');
  redis = null;
}
const localCache = new NodeCache({ stdTTL: CACHE_TTL, checkperiod: 60 });

// rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: RATE_LIMIT_PER_MIN,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// helpers for cache
async function cacheSet(key, value, ttl = CACHE_TTL) {
  if (redis) {
    // store JSON/string or Buffer separately
    if (Buffer.isBuffer(value)) {
      await redis.setBuffer(key, value, 'EX', ttl);
    } else {
      await redis.set(key, JSON.stringify(value), 'EX', ttl);
    }
  } else {
    localCache.set(key, value, ttl);
  }
}

async function cacheGet(key) {
  if (redis) {
    const buf = await redis.getBuffer(key);
    if (buf) return buf;
    const str = await redis.get(key);
    if (str) {
      try { return JSON.parse(str); } catch (e) { return str; }
    }
    return null;
  } else {
    return localCache.get(key);
  }
}

// API-key management (store in redis hash "api_keys" => value JSON {id,name,created})
async function createApiKey(name) {
  const key = uuidv4().replace(/-/g,'');
  const record = { id: key, name, created: Date.now() };
  if (redis) {
    await redis.hset('api_keys', key, JSON.stringify(record));
    if (API_KEY_TTL > 0) await redis.expire('api_keys', API_KEY_TTL);
  } else {
    localCache.set('apikey:' + key, record, API_KEY_TTL || 0);
  }
  return record;
}

async function getApiKeyRecord(key) {
  if (redis) {
    const r = await redis.hget('api_keys', key);
    return r ? JSON.parse(r) : null;
  } else {
    return localCache.get('apikey:' + key) || null;
  }
}

// SSRF / hostname public check
async function isPublicAddress(hostname) {
  try {
    let addrs = [];
    try { addrs = addrs.concat(await dns.resolve4(hostname)); } catch (e) {}
    try { addrs = addrs.concat(await dns.resolve6(hostname)); } catch (e) {}
    if (addrs.length === 0) {
      const lk = await dns.lookup(hostname, { all: true });
      addrs = lk.map(r => r.address);
    }
    if (addrs.length === 0) return false;
    for (const addr of addrs) {
      let parsed;
      try { parsed = ipaddr.parse(addr); } catch (e) { return false; }
      const range = parsed.range();
      if (range === 'loopback' || range === 'private' || range === 'linkLocal' ||
          range === 'uniqueLocal' || range === 'reserved' || range === 'carrierGradeNat') {
        return false;
      }
    }
    return true;
  } catch (err) {
    console.error('isPublicAddress error', err);
    return false;
  }
}

// middleware: require JWT (or legacy x-api-key for token exchange)
function requireAuth(req, res, next) {
  const auth = req.get('authorization') || '';
  const apiKeyHeader = req.get('x-api-key') || '';
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      return next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  } else if (apiKeyHeader) {
    // allow x-api-key only for backward compatibility (but prefer /auth/token)
    getApiKeyRecord(apiKeyHeader).then(r => {
      if (!r) return res.status(401).json({ error: 'Invalid API key' });
      req.user = { apiKey: apiKeyHeader, name: r.name };
      return next();
    }).catch(err => {
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    });
  } else {
    return res.status(401).json({ error: 'Missing auth' });
  }
}

// Admin endpoint: create API key
app.post('/auth/create-key', async (req, res) => {
  const admin = req.get('x-admin-key') || '';
  if (admin !== ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  const name = (req.body && req.body.name) ? req.body.name : 'unnamed';
  const rec = await createApiKey(name);
  // return the raw api key to caller (store it securely)
  return res.json({ apiKey: rec.id, record: rec });
});

// Token issuance: exchange API key for short-lived JWT
app.post('/auth/token', async (req, res) => {
  const key = req.get('x-api-key') || (req.body && req.body.apiKey) || '';
  if (!key) return res.status(400).json({ error: 'missing api key' });
  const rec = await getApiKeyRecord(key);
  if (!rec) return res.status(401).json({ error: 'invalid api key' });
  const payload = { sub: rec.id, name: rec.name };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL });
  return res.json({ token, expires_in: JWT_TTL });
});

// /render endpoint
app.post('/render', requireAuth, async (req, res) => {
  try {
    const url = req.body && req.body.url;
    if (!url) return res.status(400).json({ error: 'missing url' });
    // basic URL format check
    let parsed;
    try {
      parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return res.status(400).json({ error: 'unsupported protocol' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'invalid url' });
    }

    // SSRF check
    const okHost = await isPublicAddress(parsed.hostname);
    if (!okHost) return res.status(403).json({ error: 'hostname resolves to non-public address' });

    // Cache key
    const cacheKey = `render:${url}`;
    const cached = await cacheGet(cacheKey);
    if (cached) return res.json(cached);

    // Launch Puppeteer (using bundled chromium). For production, run in container with limits.
    const browser = await puppeteer.launch({
      args: ['--no-sandbox','--disable-setuid-sandbox'],
      defaultViewport: { width: 1280, height: 720 }
    });
    const page = await browser.newPage();
    await page.setUserAgent('WebRendererBot/1.0 (+https://your.site/)');
    await page.setDefaultNavigationTimeout(30000);
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

    // Get page content and parse via Readability
    const html = await page.content();
    const dom = new JSDOM(html, { url: url });
    const reader = new Readability(dom.window.document);
    const article = reader.parse(); // may be null

    const text = (article && article.textContent) ? article.textContent : (await page.evaluate(() => (document.body?document.body.innerText:'')));

    // screenshot
    const screenshotBuffer = await page.screenshot({ encoding: 'binary', fullPage: false, type: 'png' });
    const title = article && article.title ? article.title : await page.title().catch(()=>'');
    await browser.close();

    // store image -> token
    const token = crypto.createHash('sha256').update(url + Date.now().toString()).digest('hex').slice(0,32);
    await cacheSet(`image:${token}`, screenshotBuffer, CACHE_TTL); // binary
    const payload = {
      url,
      title,
      text: (text || '').slice(0, 20000),
      articleHtml: article && article.content ? article.content : null,
      imageUrl: `${req.protocol}://${req.get('host')}/image/${token}`,
      token
    };
    await cacheSet(cacheKey, payload, CACHE_TTL);
    return res.json(payload);
  } catch (err) {
    console.error('render error', err);
    return res.status(500).json({ error: 'render failed', detail: err.toString() });
  }
});

// image retrieval
app.get('/image/:token', async (req, res) => {
  const token = req.params.token;
  const buf = await cacheGet(`image:${token}`);
  if (!buf) return res.status(404).send('Not found/expired');
  res.set('Content-Type', 'image/png');
  res.send(buf);
});

app.listen(PORT, () => console.log(`Renderer server listening on ${PORT}`));
