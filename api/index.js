// Orbweave: one function that serves every /api/<name> address.
require("@vercel/blob"); // static require so Vercel installs and bundles the storage library
const __real = require;
const __mods = {};
function __req(name) {
  if (name.indexOf("./") === 0) return __mods[name.slice(2)];
  return __real(name);
}

// ===== _db =====
__mods["_db"] = (function (module, exports, require) {
// Shared helper (underscore = not a public URL).
// Talks to a Redis database over HTTPS (Upstash, added from the Vercel Storage tab),
// so no extra npm package is needed. Also hashes and checks passwords.
//
// Env vars (added automatically when you connect the database to the project):
//   KV_REST_API_URL + KV_REST_API_TOKEN   (or UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)

const crypto = require("crypto");

function conf() {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  if (!url || !token) throw Object.assign(new Error("database not configured"), { code: "NODB" });
  return { url, token };
}

function configured() {
  try { conf(); return true; } catch (e) { return false; }
}

async function cmd(...args) {
  const { url, token } = conf();
  const r = await fetch(url, {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(args.map((a) => String(a))),
  });
  let d = {};
  try { d = await r.json(); } catch (e) { /* ignore */ }
  if (!r.ok || d.error) throw new Error(d.error || "database error");
  return d.result;
}

// Counts an attempt and returns how many there have been in the current window.
async function rateHit(key, windowSec) {
  const n = await cmd("INCR", key);
  if (n === 1) await cmd("EXPIRE", key, windowSec);
  return n;
}

function scrypt(pw, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(pw), salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k)));
  });
}

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const k = await scrypt(pw, salt);
  return { salt: salt.toString("base64"), hash: k.toString("base64") };
}

async function verifyPassword(pw, rec) {
  const k = await scrypt(pw, Buffer.from(rec.salt, "base64"));
  const h = Buffer.from(rec.hash, "base64");
  return h.length === k.length && crypto.timingSafeEqual(h, k);
}

async function getUser(name) {
  const raw = await cmd("GET", "user:" + name);
  return raw ? JSON.parse(raw) : null;
}

async function putUser(u) {
  await cmd("SET", "user:" + u.name, JSON.stringify(u));
}

module.exports = { cmd, configured, rateHit, hashPassword, verifyPassword, getUser, putUser };

return module.exports;
})({ exports: {} }, {}, __req);

// ===== _auth =====
__mods["_auth"] = (function (module, exports, require) {
// Shared helpers (the leading underscore stops Vercel from exposing this file as a URL).
//
// Invite codes are signed, so they need no database:  abc234-0kq2-1a2b3c4d5e6f
//   id (6 chars) - expiry day (base36) - signature
// A code is used once, to create an account. After that members sign in with a
// username and password. Sessions are signed cookies that last 90 days and are
// checked against the account every time (removing a member or resetting a
// password signs their old devices out).
//
// Required env var: SESSION_SECRET (random string, 32+ characters)
// Optional env var: REVOKED_CODES (comma-separated code ids to block, e.g. "abc234,xyz789")

const crypto = require("crypto");
const db = require("./_db");

const DAY = 86400000;
const ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const COOKIE = "ow_member";

function secret() {
  const s = process.env.SESSION_SECRET || "";
  if (s.length < 32) throw new Error("SESSION_SECRET is missing or too short");
  return s;
}
function hmac(data) {
  return crypto.createHmac("sha256", secret()).update(data).digest("hex");
}
function safeEq(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function revoked() {
  return (process.env.REVOKED_CODES || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
}

function newCode(days) {
  let id = "";
  const bytes = crypto.randomBytes(6);
  for (let i = 0; i < 6; i++) id += ALPHABET[bytes[i] % ALPHABET.length];
  const exp = Math.floor(Date.now() / DAY) + Math.max(1, Math.min(365, days | 0));
  const expStr = exp.toString(36).padStart(4, "0");
  const sig = hmac("code:" + id + expStr).slice(0, 12);
  return `${id}-${expStr}-${sig}`;
}

function checkCode(raw) {
  const m = /^([a-z2-9]{6})-([0-9a-z]{4})-([0-9a-f]{12})$/.exec(String(raw || "").trim().toLowerCase());
  if (!m) return null;
  const [, id, expStr, sig] = m;
  if (!safeEq(hmac("code:" + id + expStr).slice(0, 12), sig)) return null;
  if (parseInt(expStr, 36) < Math.floor(Date.now() / DAY)) return null;
  if (revoked().includes(id)) return null;
  return { id };
}

const SESSION_DAYS = 90;

function sessionCookie(user) {
  const payload = Buffer.from(JSON.stringify({ u: user.name, id: user.uid || "", sv: user.sv, exp: Date.now() + SESSION_DAYS * DAY })).toString("base64url");
  const token = payload + "." + hmac("sess:" + payload);
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}
function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

// Returns { user } for a signed-in member, or null.
async function readSession(req) {
  try {
    const header = req.headers.cookie || "";
    const pair = header.split(";").map((s) => s.trim()).find((s) => s.startsWith(COOKIE + "="));
    if (!pair) return null;
    const token = pair.slice(COOKIE.length + 1);
    const [payload, sig] = token.split(".");
    if (!payload || !sig || !safeEq(hmac("sess:" + payload), sig)) return null;
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (!data.exp || data.exp < Date.now() || !data.u) return null;
    const user = await db.getUser(String(data.u));
    if (!user || user.sv !== data.sv || (user.uid || "") !== (data.id || "")) return null; // uid stops an old sign-in from working on a new account that reuses a removed username
    return { user: user.name };
  } catch (e) {
    return null;
  }
}

async function readBody(req, max) {
  if (Buffer.isBuffer(req.body)) return req.body;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > max) throw Object.assign(new Error("too large"), { code: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function jsonBody(req) {
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body) ? req.body : {};
}

function isMemberBlobUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" && url.hostname.endsWith(".blob.vercel-storage.com") && url.pathname.startsWith("/members/");
  } catch (e) {
    return false;
  }
}

const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  recent.push(now);
  hits.set(key, recent);
  return recent.length > max;
}
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
}

module.exports = { newCode, checkCode, sessionCookie, clearCookie, readSession, readBody, jsonBody, isMemberBlobUrl, limited, clientIp, safeEq };

return module.exports;
})({ exports: {} }, {}, __req);

// ===== _products =====
__mods["_products"] = (function (module, exports, require) {
// Shared helper (underscore = not a public URL). Each product is stored as a small
// JSON file in "products/" next to its picture. Newest first.

const { list } = require("@vercel/blob");

async function listProducts(limit) {
  const { blobs } = await list({ prefix: "products/", limit: 500 });
  const metas = blobs
    .filter((b) => b.pathname.endsWith(".json"))
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt))
    .slice(0, limit || 60);

  const items = await Promise.all(
    metas.map(async (b) => {
      try {
        const r = await fetch(b.url);
        if (!r.ok) return null;
        const d = await r.json();
        return { id: b.url, name: d.name, desc: d.desc, price: d.price, link: d.link, image: d.image, postedAt: d.postedAt || b.uploadedAt };
      } catch (e) {
        return null;
      }
    })
  );
  return items.filter(Boolean);
}

module.exports = { listProducts };

return module.exports;
})({ exports: {} }, {}, __req);

// ===== account =====
__mods["account"] = (function (module, exports, require) {
// GET  /api/account                          -> { user } if signed in, else 401
// GET  /api/account?info=1                   -> { inviteRequired } (public)
// POST /api/account {action:"signup", username, password, code}
// POST /api/account {action:"login", username, password}
// POST /api/account {action:"logout"}
// POST /api/account {action:"password", oldPassword, newPassword}

const { checkCode, sessionCookie, clearCookie, readSession, jsonBody, clientIp } = require("./_auth");
const crypto = require("crypto");
const db = require("./_db");

// Sign-up is open by default. Set the environment variable REQUIRE_INVITE to "yes" to require an invite code again.
function inviteRequired() { return String(process.env.REQUIRE_INVITE || "").toLowerCase() === "yes"; }

const NAME_RE = /^[a-z0-9_]{3,20}$/;
const WINDOW = 15 * 60; // seconds

let dummy = null; // used so unknown usernames take as long to check as real ones
async function burnTime(pw) {
  if (!dummy) dummy = await db.hashPassword("not-a-real-password");
  await db.verifyPassword(String(pw), dummy);
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 100;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    if (req.method === "GET") {
      if (req.query && req.query.info) return res.status(200).json({ inviteRequired: inviteRequired() });
      const s = await readSession(req);
      if (!s) return res.status(401).json({ error: "Not signed in." });
      return res.status(200).json({ user: s.user });
    }
    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).json({ error: "Method not allowed" });
    }

    const b = jsonBody(req);
    const action = String(b.action || "");
    const ip = clientIp(req);

    if (action === "logout") {
      res.setHeader("Set-Cookie", clearCookie());
      return res.status(200).json({ ok: true });
    }

    if (action === "signup") {
      // Spam trap: real people never fill this hidden field.
      if (b.website) return res.status(400).json({ error: "Could not create the account." });
      // 5 new accounts per hour per connection.
      if ((await db.rateHit("rl:signup:" + ip, 3600)) > 5) {
        return res.status(429).json({ error: "Too many sign-ups from this connection. Try again later." });
      }
      const username = String(b.username || "").trim().toLowerCase();
      const password = b.password;
      if (!NAME_RE.test(username)) {
        return res.status(400).json({ error: "Username must be 3 to 20 letters, numbers or underscores." });
      }
      if (!validPassword(password) || password.toLowerCase() === username) {
        return res.status(400).json({ error: "Password must be 8 to 100 characters and not your username." });
      }
      const needCode = inviteRequired();
      let code = null;
      if (needCode) {
        code = checkCode(b.code);
        if (!code) return res.status(401).json({ error: "That invite code is not valid or has expired." });
      }

      if (await db.getUser(username)) return res.status(409).json({ error: "That username is taken." });

      if (needCode) {
        // A code can create only one account.
        const claimed = await db.cmd("SET", "codeused:" + code.id, username, "NX");
        if (!claimed) return res.status(409).json({ error: "That invite code has already been used." });
      }

      const { salt, hash } = await db.hashPassword(password);
      const user = { name: username, uid: crypto.randomBytes(8).toString("hex"), salt, hash, sv: 1, created: new Date().toISOString(), code: code ? code.id : "" };
      const created = await db.cmd("SET", "user:" + username, JSON.stringify(user), "NX");
      if (!created) {
        if (needCode) await db.cmd("DEL", "codeused:" + code.id); // someone took the name a moment ago: free the code
        return res.status(409).json({ error: "That username is taken." });
      }
      await db.cmd("SADD", "users", username);
      res.setHeader("Set-Cookie", sessionCookie(user));
      return res.status(200).json({ ok: true, user: username });
    }

    if (action === "login") {
      const username = String(b.username || "").trim().toLowerCase();
      const password = String(b.password || "");
      if ((await db.rateHit("rl:login:ip:" + ip, WINDOW)) > 30) {
        return res.status(429).json({ error: "Too many tries. Wait a few minutes." });
      }
      if (NAME_RE.test(username) && (await db.rateHit("rl:login:u:" + username, WINDOW)) > 8) {
        return res.status(429).json({ error: "Too many tries for this account. Wait 15 minutes." });
      }
      const user = NAME_RE.test(username) ? await db.getUser(username) : null;
      if (!user) {
        await burnTime(password);
        return res.status(401).json({ error: "Wrong username or password." });
      }
      if (!(await db.verifyPassword(password, user))) {
        return res.status(401).json({ error: "Wrong username or password." });
      }
      await db.cmd("DEL", "rl:login:u:" + username);
      res.setHeader("Set-Cookie", sessionCookie(user));
      return res.status(200).json({ ok: true, user: user.name });
    }

    if (action === "password") {
      const s = await readSession(req);
      if (!s) return res.status(401).json({ error: "Sign in first." });
      if ((await db.rateHit("rl:pw:" + s.user, WINDOW)) > 10) {
        return res.status(429).json({ error: "Too many tries. Wait a few minutes." });
      }
      if (!validPassword(b.newPassword) || String(b.newPassword).toLowerCase() === s.user) {
        return res.status(400).json({ error: "New password must be 8 to 100 characters and not your username." });
      }
      const user = await db.getUser(s.user);
      if (!user || !(await db.verifyPassword(String(b.oldPassword || ""), user))) {
        return res.status(401).json({ error: "Your current password is wrong." });
      }
      const { salt, hash } = await db.hashPassword(b.newPassword);
      user.salt = salt; user.hash = hash; user.sv = (user.sv || 1) + 1; // signs out other devices
      await db.putUser(user);
      res.setHeader("Set-Cookie", sessionCookie(user));
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: "Bad request" });
  } catch (e) {
    if (e && e.code === "NODB") return res.status(503).json({ error: "Accounts are not set up yet." });
    return res.status(500).json({ error: "Something went wrong. Try again in a moment." });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== messages =====
__mods["messages"] = (function (module, exports, require) {
// Direct messages between signed-in members.
//
// GET  /api/messages                    -> { inbox: [{user,last,at,unread}], unread }
// GET  /api/messages?list=members       -> { members: [usernames except you] }
// GET  /api/messages?with=<username>    -> { user, messages: [{from,text,at}], blocked }  (marks it read)
// POST /api/messages {action:"send", to, text}
// POST /api/messages {action:"block"|"unblock", user}
// POST /api/messages {action:"report", with, note}   -> sends the last messages of that chat to the owner

const crypto = require("crypto");
const db = require("./_db");
const { readSession, jsonBody } = require("./_auth");

const NAME_RE = /^[a-z0-9_]{3,20}$/;
const MAX_TEXT = 1000;
const KEEP = 500; // messages kept per conversation

function pairKey(a, b) {
  return "conv:" + [a, b].sort().join(":");
}
function clean(s, max) {
  // keep letters, punctuation and line breaks; drop control characters
  return String(s == null ? "" : s).replace(/\r/g, "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").trim().slice(0, max);
}
function parse(raw) {
  try { return JSON.parse(raw); } catch (e) { return null; }
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    const session = await readSession(req);
    if (!session) return res.status(401).json({ error: "Sign in to use messages." });
    const me = session.user;

    if (req.method === "GET") {
      const q = req.query || {};

      if (q.list === "members") {
        const names = (await db.cmd("SMEMBERS", "users")) || [];
        return res.status(200).json({ members: names.filter((n) => n !== me).sort() });
      }

      if (q.with) {
        const other = String(q.with).toLowerCase();
        if (!NAME_RE.test(other)) return res.status(400).json({ error: "Bad username." });
        const raw = (await db.cmd("LRANGE", pairKey(me, other), -200, -1)) || [];
        const messages = raw.map(parse).filter(Boolean).map((m) => ({ from: m.from, text: m.text, at: m.at }));
        const ent = parse(await db.cmd("HGET", "inbox:" + me, other));
        if (ent && ent.unread) {
          ent.unread = 0;
          await db.cmd("HSET", "inbox:" + me, other, JSON.stringify(ent));
        }
        const blocked = (await db.cmd("SISMEMBER", "block:" + me, other)) === 1;
        return res.status(200).json({ user: other, messages, blocked });
      }

      const flat = (await db.cmd("HGETALL", "inbox:" + me)) || [];
      const items = [];
      for (let i = 0; i + 1 < flat.length; i += 2) {
        const e = parse(flat[i + 1]);
        if (e) items.push({ user: flat[i], last: e.last || "", at: e.at || "", unread: e.unread || 0 });
      }
      items.sort((a, b) => String(b.at).localeCompare(String(a.at)));
      const unread = items.reduce((n, i) => n + i.unread, 0);
      return res.status(200).json({ inbox: items, unread });
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).json({ error: "Method not allowed" });
    }

    const b = jsonBody(req);
    const action = String(b.action || "send");

    if (action === "send") {
      if ((await db.rateHit("rl:dm:" + me, 600)) > 40) {
        return res.status(429).json({ error: "You're sending too fast. Wait a few minutes." });
      }
      const to = String(b.to || "").trim().toLowerCase();
      const text = clean(b.text, MAX_TEXT);
      if (!NAME_RE.test(to) || to === me) return res.status(400).json({ error: "Choose another member to message." });
      if (!text) return res.status(400).json({ error: "Write a message first." });
      if (!(await db.getUser(to))) return res.status(404).json({ error: "No member with that username." });
      if ((await db.cmd("SISMEMBER", "block:" + to, me)) === 1) {
        return res.status(403).json({ error: "This member isn't accepting messages from you." });
      }
      if ((await db.cmd("SISMEMBER", "block:" + me, to)) === 1) {
        return res.status(403).json({ error: "You blocked this member. Unblock them to send a message." });
      }

      const at = new Date().toISOString();
      const key = pairKey(me, to);
      await db.cmd("RPUSH", key, JSON.stringify({ from: me, text, at }));
      await db.cmd("LTRIM", key, -KEEP, -1);

      const preview = text.replace(/\s+/g, " ").slice(0, 60);
      const theirs = parse(await db.cmd("HGET", "inbox:" + to, me)) || {};
      await db.cmd("HSET", "inbox:" + to, me, JSON.stringify({ last: preview, at, unread: (theirs.unread || 0) + 1 }));
      await db.cmd("HSET", "inbox:" + me, to, JSON.stringify({ last: preview, at, unread: 0 }));
      return res.status(200).json({ ok: true });
    }

    if (action === "block" || action === "unblock") {
      const user = String(b.user || "").trim().toLowerCase();
      if (!NAME_RE.test(user) || user === me) return res.status(400).json({ error: "Bad username." });
      await db.cmd(action === "block" ? "SADD" : "SREM", "block:" + me, user);
      return res.status(200).json({ ok: true, blocked: action === "block" });
    }

    if (action === "report") {
      if ((await db.rateHit("rl:report:" + me, 3600)) > 5) {
        return res.status(429).json({ error: "Too many reports. Try again later." });
      }
      const about = String(b.with || "").trim().toLowerCase();
      if (!NAME_RE.test(about) || about === me) return res.status(400).json({ error: "Bad username." });
      const raw = (await db.cmd("LRANGE", pairKey(me, about), -20, -1)) || [];
      const excerpt = raw.map(parse).filter(Boolean).map((m) => ({ from: m.from, text: m.text, at: m.at }));
      const report = {
        id: crypto.randomBytes(6).toString("hex"),
        by: me, about, note: clean(b.note, 300), at: new Date().toISOString(), excerpt,
      };
      await db.cmd("RPUSH", "reports", JSON.stringify(report));
      await db.cmd("LTRIM", "reports", -200, -1);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: "Bad request" });
  } catch (e) {
    if (e && e.code === "NODB") return res.status(503).json({ error: "Messages are not set up yet." });
    return res.status(500).json({ error: "Something went wrong. Try again in a moment." });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== members =====
__mods["members"] = (function (module, exports, require) {
// Members only (needs an account sign-in).
// GET  /api/members  -> { user, images: [ {src, by}, ... ] } newest first
// POST /api/members  (raw JPEG bytes) -> saves a picture under your username (held for review unless sign-up is invite-only)

const { put, list } = require("@vercel/blob");
const { readSession, readBody, limited } = require("./_auth");

const MAX_BYTES = 2 * 1024 * 1024;

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const session = await readSession(req);
  if (!session) return res.status(401).json({ error: "Sign in to see this." });

  if (req.method === "GET") {
    try {
      const { blobs } = await list({ prefix: "members/", limit: 200 });
      blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
      return res.status(200).json({
        user: session.user,
        images: blobs.map((b) => ({
          src: "/api/member-image?u=" + encodeURIComponent(b.url),
          by: (b.pathname.split("/")[1] || "").replace(/[^a-z0-9_]/g, ""),
        })),
      });
    } catch (e) {
      return res.status(200).json({ user: session.user, images: [] });
    }
  }

  if (req.method === "POST") {
    if (limited("mem:" + session.user, 20, 10 * 60 * 1000)) {
      return res.status(429).json({ error: "Too many uploads" });
    }
    try {
      const buf = await readBody(req, MAX_BYTES);
      if (buf.length > MAX_BYTES) return res.status(413).json({ error: "Too large" });
      if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
        return res.status(400).json({ error: "Not a JPEG" });
      }
      // With open sign-up, a new picture waits for your approval. With invite-only sign-up it posts straight away.
      const review = String(process.env.REQUIRE_INVITE || "").toLowerCase() !== "yes";
      await put((review ? "memberpending/" : "members/") + session.user + "/pic.jpg", buf, { access: "public", contentType: "image/jpeg", addRandomSuffix: true });
      return res.status(200).json({ ok: true, pending: review });
    } catch (e) {
      if (e && e.code === 413) return res.status(413).json({ error: "Too large" });
      return res.status(500).json({ error: "Upload failed" });
    }
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== member-image =====
__mods["member-image"] = (function (module, exports, require) {
// GET /api/member-image?u=<storage url>
// Serves a members-only picture only to signed-in members, so the picture
// never needs to be linked directly from the page.

const { readSession, isMemberBlobUrl } = require("./_auth");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).end();
  }
  if (!(await readSession(req))) return res.status(401).end();

  const u = String(req.query.u || "");
  if (!isMemberBlobUrl(u)) return res.status(400).end();

  try {
    const r = await fetch(u);
    if (!r.ok) return res.status(404).end();
    const buf = Buffer.from(await r.arrayBuffer());
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Cache-Control", "private, max-age=3600");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Robots-Tag", "noindex");
    return res.status(200).send(buf);
  } catch (e) {
    return res.status(502).end();
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== products =====
__mods["products"] = (function (module, exports, require) {
// GET /api/products -> { products: [ {name, desc, price, link, image, postedAt}, ... ] } newest first

const { listProducts } = require("./_products");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  try {
    const items = await listProducts(60);
    res.setHeader("Cache-Control", "s-maxage=60, stale-while-revalidate=300");
    return res.status(200).json({
      products: items.map((p) => ({ name: p.name, desc: p.desc, price: p.price, link: p.link, image: p.image, postedAt: p.postedAt })),
    });
  } catch (e) {
    return res.status(200).json({ products: [] });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== upload =====
__mods["upload"] = (function (module, exports, require) {
// POST /api/upload  (body: raw JPEG bytes, Content-Type: image/jpeg)
// Stores the picture in the private-review area ("pending/"). It is NOT shown on
// the wall until you approve it at /api/admin?key=YOUR_ADMIN_KEY.

const { put } = require("@vercel/blob");

const MAX_BYTES = 2 * 1024 * 1024; // 2 MB (the page already shrinks pictures to fit)

// Light per-instance limiter. For strong limits, also add a Vercel Firewall rate-limit rule on /api/upload.
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > 5; // 5 pictures per 10 minutes per visitor
}

async function readBody(req) {
  if (Buffer.isBuffer(req.body)) return req.body;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BYTES) throw Object.assign(new Error("too large"), { code: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (limited(ip)) return res.status(429).json({ error: "Too many uploads" });

  try {
    const buf = await readBody(req);
    if (buf.length > MAX_BYTES) return res.status(413).json({ error: "Too large" });

    // Must really be a JPEG (starts FF D8 FF), not just labelled as one.
    if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
      return res.status(400).json({ error: "Not a JPEG" });
    }

    await put("pending/pic.jpg", buf, {
      access: "public",
      contentType: "image/jpeg",
      addRandomSuffix: true,
    });
    return res.status(200).json({ ok: true });
  } catch (e) {
    if (e && e.code === 413) return res.status(413).json({ error: "Too large" });
    return res.status(500).json({ error: "Upload failed" });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== wall =====
__mods["wall"] = (function (module, exports, require) {
// GET /api/wall  -> { images: [url, ...] }  newest first, approved pictures only.

const { list } = require("@vercel/blob");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  try {
    const { blobs } = await list({ prefix: "approved/", limit: 100 });
    blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    res.setHeader("Cache-Control", "s-maxage=60, stale-while-revalidate=300");
    return res.status(200).json({ images: blobs.map((b) => b.url) });
  } catch (e) {
    return res.status(200).json({ images: [] });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== admin =====
__mods["admin"] = (function (module, exports, require) {
// Your private control page. Open:  /api/admin?key=YOUR_ADMIN_KEY
//
// What you can do here:
//   1. Create invite codes for new members
//   2. Approve or delete public-wall pictures waiting for review
//   3. Delete member pictures
//
// Env vars: ADMIN_KEY (16+ chars), SESSION_SECRET (32+ chars), BLOB_READ_WRITE_TOKEN (added by Vercel Blob)

const { list, copy, del, put } = require("@vercel/blob");
const crypto = require("crypto");
const { newCode, isMemberBlobUrl, jsonBody } = require("./_auth");
const { listProducts } = require("./_products");
const db = require("./_db");
const crypto2 = require("crypto");
const NAME_RE = /^[a-z0-9_]{3,20}$/;
const TEMP_CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function tempPassword() {
  const b = crypto2.randomBytes(12);
  let p = "";
  for (let i = 0; i < 12; i++) p += TEMP_CHARS[b[i] % TEMP_CHARS.length];
  return p;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function cleanText(s, max) {
  return String(s == null ? "" : s).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, max);
}

function authorized(req) {
  const given = String((req.query && req.query.key) || "");
  const expected = String(process.env.ADMIN_KEY || "");
  if (!expected || expected.length < 16) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isBlobUrlUnder(u, folder) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" && url.hostname.endsWith(".blob.vercel-storage.com") && url.pathname.startsWith("/" + folder + "/");
  } catch (e) {
    return false;
  }
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  if (!authorized(req)) return res.status(401).send("Unauthorized");

  if (req.method === "POST") {
    const b = jsonBody(req);
    const { action, url, days, username } = b;
    try {
      if (action === "newcode") {
        const d = Number(days);
        if (![7, 30, 90].includes(d)) return res.status(400).json({ error: "Bad length" });
        return res.status(200).json({ code: newCode(d), days: d });
      }
      if (action === "approve" && isBlobUrlUnder(url, "pending")) {
        await copy(url, "approved/pic.jpg", { access: "public", addRandomSuffix: true });
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "delete" && isBlobUrlUnder(url, "pending")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deletemember" && isMemberBlobUrl(url)) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "addproduct") {
        const b = jsonBody(req);
        const name = cleanText(b.name, 80);
        const desc = cleanText(b.desc, 400);
        const price = cleanText(b.price, 30);
        let link = cleanText(b.link, 300);
        if (!name) return res.status(400).json({ error: "Add a product name." });
        if (link && !/^https?:\/\/[^\s]+$/i.test(link)) return res.status(400).json({ error: "The buy link must start with http:// or https://" });
        const raw = String(b.image || "").replace(/^data:image\/jpeg;base64,/, "");
        const buf = Buffer.from(raw, "base64");
        if (buf.length < 4 || buf.length > 2 * 1024 * 1024 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
          return res.status(400).json({ error: "Add a picture (JPEG, up to 2 MB)." });
        }
        const img = await put("products/img.jpg", buf, { access: "public", contentType: "image/jpeg", addRandomSuffix: true });
        const meta = { name, desc, price, link, image: img.url, postedAt: new Date().toISOString() };
        await put("products/p.json", JSON.stringify(meta), { access: "public", contentType: "application/json", addRandomSuffix: true });
        return res.status(200).json({ ok: true });
      }
      if (action === "removeuser" && NAME_RE.test(String(username))) {
        // 1. conversations: delete them and remove this member from the other person's inbox
        const flat = (await db.cmd("HGETALL", "inbox:" + username)) || [];
        for (let i = 0; i < flat.length; i += 2) {
          const other = flat[i];
          await db.cmd("DEL", "conv:" + [username, other].sort().join(":"));
          await db.cmd("HDEL", "inbox:" + other, username);
        }
        await db.cmd("DEL", "inbox:" + username);
        await db.cmd("DEL", "block:" + username);
        // 2. forget them in everyone else's block lists, so a future member with this name starts clean
        const everyone = (await db.cmd("SMEMBERS", "users")) || [];
        for (const u of everyone) await db.cmd("SREM", "block:" + u, username);
        // 3. their pictures
        try {
          const mine = (await list({ prefix: "members/" + username + "/", limit: 500 })).blobs;
          for (const b of mine) await del(b.url);
          const waiting = (await list({ prefix: "memberpending/" + username + "/", limit: 500 })).blobs;
          for (const b of waiting) await del(b.url);
        } catch (e) { /* pictures can still be deleted by hand below */ }
        // 4. the account itself
        await db.cmd("DEL", "user:" + username);
        await db.cmd("SREM", "users", username);
        return res.status(200).json({ ok: true });
      }
      if (action === "dismissreport" && /^[a-f0-9]{12}$/.test(String(b.id || ""))) {
        const rows = (await db.cmd("LRANGE", "reports", 0, -1)) || [];
        for (const raw of rows) {
          try { if (JSON.parse(raw).id === b.id) { await db.cmd("LREM", "reports", 1, raw); break; } } catch (e) { /* skip */ }
        }
        return res.status(200).json({ ok: true });
      }
      if (action === "resetpw" && NAME_RE.test(String(username))) {
        const u = await db.getUser(username);
        if (!u) return res.status(404).json({ error: "No such member." });
        const temp = tempPassword();
        const h = await db.hashPassword(temp);
        u.salt = h.salt; u.hash = h.hash; u.sv = (u.sv || 1) + 1;
        await db.putUser(u);
        return res.status(200).json({ temp });
      }
      if (action === "approvemember" && isBlobUrlUnder(url, "memberpending")) {
        const owner = (new URL(url).pathname.split("/")[2] || "").replace(/[^a-z0-9_]/g, "");
        if (!owner) return res.status(400).json({ error: "Bad request" });
        await copy(url, "members/" + owner + "/pic.jpg", { access: "public", addRandomSuffix: true });
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deletememberpending" && isBlobUrlUnder(url, "memberpending")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deleteinvite" && isBlobUrlUnder(url, "invites")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deleteorder" && isBlobUrlUnder(url, "orders")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deleteproduct" && isBlobUrlUnder(url, "products") && /\.json$/.test(new URL(url).pathname)) {
        try {
          const r = await fetch(url);
          if (r.ok) {
            const d = await r.json();
            if (isBlobUrlUnder(d.image, "products")) await del(d.image);
          }
        } catch (e) { /* still remove the listing below */ }
        await del(url);
        return res.status(200).json({ ok: true });
      }
      return res.status(400).json({ error: "Bad request" });
    } catch (e) {
      return res.status(500).json({ error: "Failed" });
    }
  }

  if (req.method !== "GET") return res.status(405).send("Method not allowed");

  const pending = (await list({ prefix: "pending/", limit: 200 })).blobs;
  pending.sort((a, b) => new Date(a.uploadedAt) - new Date(b.uploadedAt));
  const memberPending = (await list({ prefix: "memberpending/", limit: 200 })).blobs;
  memberPending.sort((a, b) => new Date(a.uploadedAt) - new Date(b.uploadedAt));
  const members = (await list({ prefix: "members/", limit: 200 })).blobs;
  members.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  const key = encodeURIComponent(req.query.key);
  let products = [];
  try { products = await listProducts(60); } catch (e) { products = []; }

  let orders = [];
  try {
    const ob = (await list({ prefix: "orders/", limit: 200 })).blobs
      .filter((b) => b.pathname.endsWith(".json"))
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    orders = (await Promise.all(ob.map(async (b) => {
      try {
        const r = await fetch(b.url);
        if (!r.ok) return null;
        return Object.assign(await r.json(), { id: b.url });
      } catch (e) { return null; }
    }))).filter(Boolean);
  } catch (e) { orders = []; }

  let invites = [];
  try {
    const ib = (await list({ prefix: "invites/", limit: 200 })).blobs
      .filter((b) => b.pathname.endsWith(".json"))
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    invites = (await Promise.all(ib.map(async (b) => {
      try {
        const r = await fetch(b.url);
        if (!r.ok) return null;
        return Object.assign(await r.json(), { id: b.url });
      } catch (e) { return null; }
    }))).filter(Boolean);
  } catch (e) { invites = []; }

  const inviteCard = (i) => `<div class="c" data-url="${esc(i.id)}" data-kind="invite" data-email="${esc(i.email)}">
      <div><strong><a href="mailto:${esc(i.email)}">${esc(i.email)}</a></strong><br><small>${esc(String(i.at || "").slice(0, 16).replace("T", " "))} UTC</small></div>
      <div><button class="mk">Create code</button><button class="no">Delete</button></div>
      <div class="ic" style="margin-top:8px"></div>
    </div>`;

  let users = [];
  let dbOk = true;
  try {
    const names = await db.cmd("SMEMBERS", "users");
    if (names && names.length) {
      const raws = await db.cmd("MGET", ...names.map((n) => "user:" + n));
      users = raws.filter(Boolean).map((r) => JSON.parse(r)).sort((a, b) => String(b.created).localeCompare(String(a.created)));
    }
  } catch (e) { dbOk = false; }

  const userCard = (u) => `<div class="c" data-kind="user" data-user="${esc(u.name)}">
      <div><strong>@${esc(u.name)}</strong><br><small>Joined ${esc(String(u.created || "").slice(0, 10))}</small></div>
      <div><button class="rp">Reset password</button><button class="no">Remove</button></div>
      <div class="tp" style="font-family:ui-monospace,monospace;font-size:1.05rem;margin-top:8px;user-select:all"></div>
    </div>`;

  let reports = [];
  try {
    reports = ((await db.cmd("LRANGE", "reports", 0, -1)) || [])
      .map((r) => { try { return JSON.parse(r); } catch (e) { return null; } })
      .filter(Boolean)
      .reverse();
  } catch (e) { reports = []; }

  const reportCard = (r) => `<div class="c" data-kind="report" data-id="${esc(r.id)}" data-about="${esc(r.about)}">
      <div><strong>@${esc(r.by)} reported @${esc(r.about)}</strong><br><small>${esc(String(r.at || "").slice(0, 16).replace("T", " "))} UTC</small></div>
      ${r.note ? "<p><i>" + esc(r.note) + "</i></p>" : ""}
      <div style="font-size:.9rem;background:#f3f4f8;border-radius:8px;padding:8px;max-height:220px;overflow:auto">${
        (r.excerpt || []).map((m) => "<div><b>@" + esc(m.from) + ":</b> " + esc(m.text) + "</div>").join("") || "<i>No messages</i>"
      }</div>
      <div><button class="no rm">Remove @${esc(r.about)}</button><button class="dm">Dismiss</button></div>
    </div>`;

  const orderCard = (o) => {
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(o.contact || "");
    const contact = isEmail ? `<a href="mailto:${esc(o.contact)}">${esc(o.contact)}</a>` : esc(o.contact);
    return `<div class="c" data-url="${esc(o.id)}" data-kind="order">
      <div><strong>${esc(o.product || "Product")}</strong><br><small>${esc(String(o.at || "").slice(0, 16).replace("T", " "))} UTC</small></div>
      <p><b>${esc(o.name)}</b><br>${contact}</p>
      <p>${esc(o.message) || "<i>No message</i>"}</p>
      <div><button class="no">Delete</button></div>
    </div>`;
  };

  const productCard = (p) => `<div class="c" data-url="${esc(p.id)}" data-kind="product">
      <img src="${esc(p.image)}" alt="${esc(p.name)}" loading="lazy">
      <div><strong>${esc(p.name)}</strong>${p.price ? " &middot; " + esc(p.price) : ""}<br><small>${esc(String(p.postedAt).slice(0, 10))}</small></div>
      <div><button class="no">Delete</button></div>
    </div>`;

  const card = (b, kind) => `<div class="c" data-url="${b.url}" data-kind="${kind}">
      <img src="${b.url}" alt="Picture to review" loading="lazy">
      ${kind === "member" || kind === "memberpending" ? "<small>Posted by @" + esc((b.pathname.split("/")[1] || "")) + "</small>" : ""}
      <div>${kind === "pending" || kind === "memberpending" ? '<button class="ok">Approve</button>' : ""}<button class="no">Delete</button></div>
    </div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>Orbweave admin</title>
<style>
  body{font-family:system-ui,sans-serif;margin:24px;background:#f3f4f8;color:#181b3a;max-width:1100px}
  h2{margin-top:40px}
  .g{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
  .c{background:#fff;border-radius:12px;padding:10px;border:1px solid #ccd}
  img{width:100%;border-radius:8px;display:block}
  button,select{font:inherit;padding:9px 14px;margin:10px 8px 0 0;border-radius:8px;border:0;cursor:pointer}
  button{color:#fff;background:#3a3fe0}
  .ok{background:#2a7a3b}.no{background:#b3361f}
  select{background:#fff;border:1px solid #ccd;color:#181b3a}
  input[type=text],textarea{font:inherit;width:100%;padding:9px 10px;border-radius:8px;border:1px solid #ccd;margin-top:4px}
  label{font-weight:600;display:block}
  .box{background:#fff;border:1px solid #ccd;border-radius:12px;padding:16px}
  #codes div{font-family:ui-monospace,monospace;font-size:1.1rem;margin:8px 0;user-select:all}
</style></head><body>
<h1>Orbweave admin</h1>

<h2>Invite requests (${invites.length})</h2>
<p>People who asked for an invite from the home page. Press Create code to make a 30-day code for them, then press the email link to send it. Delete the request afterwards so their email doesn't pile up.</p>
<div class="g">${invites.map(inviteCard).join("") || "<p>No invite requests yet.</p>"}</div>

<h2>Reported conversations (${reports.length})</h2>
<p>Members can report a conversation. You only see the last 20 messages of a reported chat, nothing else. Remove the member to delete their account, pictures and messages, or dismiss the report.</p>
<div class="g">${reports.map(reportCard).join("") || "<p>No reports.</p>"}</div>

<h2>Members (${users.length})</h2>
${dbOk ? "" : "<p><strong>The member database is not connected yet.</strong> In Vercel, open Storage, create an Upstash Redis database and connect it to this project, then redeploy.</p>"}
<p>Members create their own account with an invite code. If someone forgets their password, press Reset password, then send them the temporary password shown. They can change it after signing in. Remove deletes the account and signs them out everywhere.</p>
<div class="g">${users.map(userCard).join("") || "<p>No members yet.</p>"}</div>

<h2>Orders and messages (${orders.length})</h2>
<p>People who tapped "I want this" on a product. Reply to them using the contact they left, then delete the request when you're done so their details don't pile up.</p>
<div class="g">${orders.map(orderCard).join("") || "<p>No requests yet.</p>"}</div>

<h2>Post a product</h2>
<div class="box">
  <p>Fill this in and press Post. It shows at the top of the home page straight away (allow up to a minute). Come back each day to add the next one.</p>
  <form id="pf" style="display:grid;gap:10px;max-width:520px">
    <label>Picture <input type="file" id="pfImg" accept="image/jpeg,image/png,image/webp"></label>
    <img id="pfPrev" alt="Preview" style="max-width:200px;display:none">
    <label>Name <input type="text" id="pfName" maxlength="80" placeholder="Product name"></label>
    <label>Price <input type="text" id="pfPrice" maxlength="30" placeholder="$24.99"></label>
    <label>Short description <textarea id="pfDesc" maxlength="400" rows="3" placeholder="One or two sentences"></textarea></label>
    <label>Buy link (optional) <input type="text" id="pfLink" maxlength="300" placeholder="https://your-store.com/product"></label>
    <div><button type="submit" id="pfBtn">Post product</button></div>
    <div id="pfMsg" role="status"></div>
  </form>
</div>

<h2>Posted products (${products.length})</h2>
<div class="g">${products.map(productCard).join("") || "<p>No products yet.</p>"}</div>

<h2>Invite codes</h2>
<div class="box">
  <p>Sign-up is open right now, so codes are not needed. They only matter if you turn invite-only sign-up back on by adding a REQUIRE_INVITE setting with the value yes in Vercel and redeploying. Then: make a code, then email it to the person you are inviting. Each code creates one account and then stops working. A member only needs the code once, to sign up. To block an unused code early, add its first 6 letters to the REVOKED_CODES setting in Vercel and redeploy.</p>
  <label>Code works for <select id="days"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option></select></label>
  <button id="mk">Create code</button>
  <div id="codes" aria-live="polite"></div>
</div>

<h2>Wall pictures waiting for review (${pending.length})</h2>
<p>Look at each picture at full size before approving. Delete anything unsafe, illegal, or showing people who may not have agreed.</p>
<div class="g">${pending.map((b) => card(b, "pending")).join("") || "<p>Nothing waiting for review.</p>"}</div>

<h2>Member pictures waiting for review (${memberPending.length})</h2>
<p>Pictures members posted. Look at each at full size. Approve to show it to the other members, or delete anything unsafe, illegal, or showing people who may not have agreed.</p>
<div class="g">${memberPending.map((b) => card(b, "memberpending")).join("") || "<p>Nothing waiting.</p>"}</div>

<h2>Member pictures (${members.length})</h2>
<p>Members post these without review, so check them from time to time and delete anything that breaks your rules.</p>
<div class="g">${members.map((b) => card(b, "member")).join("") || "<p>No member pictures yet.</p>"}</div>

<script>
var KEY="${key}";
function post(body){
  return fetch("/api/admin?key="+KEY,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(function(r){ return r.json().catch(function(){return {};}).then(function(d){ if(!r.ok){ var e=new Error(d.error||"Failed"); throw e; } return d; }); });
}
var pfBlob=null;
document.getElementById("pfImg").onchange=function(){
  var f=this.files[0]; pfBlob=null; document.getElementById("pfPrev").style.display="none"; if(!f) return;
  var url=URL.createObjectURL(f), img=new Image();
  img.onload=function(){
    var s=Math.min(1,1400/Math.max(img.naturalWidth,img.naturalHeight));
    var c=document.createElement("canvas"); c.width=Math.round(img.naturalWidth*s); c.height=Math.round(img.naturalHeight*s);
    var x=c.getContext("2d"); x.fillStyle="#fff"; x.fillRect(0,0,c.width,c.height); x.drawImage(img,0,0,c.width,c.height);
    c.toBlob(function(b){
      URL.revokeObjectURL(url);
      var rd=new FileReader(); rd.onload=function(){ pfBlob=rd.result; var p=document.getElementById("pfPrev"); p.src=rd.result; p.style.display="block"; }; rd.readAsDataURL(b);
    },"image/jpeg",0.85);
  };
  img.onerror=function(){ alert("Could not read that picture."); };
  img.src=url;
};
document.getElementById("pf").onsubmit=function(ev){
  ev.preventDefault();
  var msg=document.getElementById("pfMsg"); msg.textContent="";
  if(!pfBlob){ msg.textContent="Choose a picture first."; return; }
  var btn=document.getElementById("pfBtn"); btn.disabled=true;
  post({action:"addproduct",image:pfBlob,name:document.getElementById("pfName").value,price:document.getElementById("pfPrice").value,desc:document.getElementById("pfDesc").value,link:document.getElementById("pfLink").value})
    .then(function(){ location.reload(); })
    .catch(function(e){ msg.textContent=e.message||"Could not post. Try again."; btn.disabled=false; });
};
document.getElementById("mk").onclick=function(){
  var d=Number(document.getElementById("days").value);
  post({action:"newcode",days:d}).then(function(r){
    var el=document.createElement("div"); el.textContent=r.code+"   (valid "+r.days+" days)";
    document.getElementById("codes").prepend(el);
  }).catch(function(){ alert("Could not create a code. Check that SESSION_SECRET is set."); });
};
document.querySelectorAll(".c").forEach(function(card){
  var kind=card.dataset.kind;
  if(kind==="invite"){
    var em=card.dataset.email;
    card.querySelector(".mk").onclick=function(){
      post({action:"newcode",days:30}).then(function(r){
        var box=card.querySelector(".ic"); box.textContent="";
        var code=document.createElement("div"); code.style.cssText="font-family:ui-monospace,monospace;user-select:all;word-break:break-all"; code.textContent=r.code; box.appendChild(code);
        var a=document.createElement("a");
        var body="Hi,\\n\\nHere is your Orbweave invite code (valid 30 days):\\n\\n"+r.code+"\\n\\nCreate your account at "+location.origin+"/members.html\\n";
        a.href="mailto:"+em+"?subject="+encodeURIComponent("Your Orbweave invite")+"&body="+encodeURIComponent(body);
        a.textContent="Email this code to them"; a.style.display="inline-block"; a.style.marginTop="6px"; box.appendChild(a);
      }).catch(function(){ alert("Could not create a code. Check that SESSION_SECRET is set."); });
    };
    card.querySelector(".no").onclick=function(){
      post({action:"deleteinvite",url:card.dataset.url}).then(function(){ card.remove(); })
        .catch(function(){ alert("That did not work. Reload and try again."); });
    };
    return;
  }
  if(kind==="report"){
    var rid=card.dataset.id, about=card.dataset.about;
    card.querySelector(".dm").onclick=function(){
      post({action:"dismissreport",id:rid}).then(function(){ card.remove(); })
        .catch(function(){ alert("That did not work. Reload and try again."); });
    };
    card.querySelector(".rm").onclick=function(){
      if(!confirm("Remove "+about+"? This deletes their account, pictures and messages.")) return;
      post({action:"removeuser",username:about}).then(function(){ return post({action:"dismissreport",id:rid}); })
        .then(function(){ card.remove(); })
        .catch(function(){ alert("That did not work. Reload and try again."); });
    };
    return;
  }
  if(kind==="user"){
    var uname=card.dataset.user;
    card.querySelector(".rp").onclick=function(){
      if(!confirm("Reset the password for "+uname+"? Their old password will stop working.")) return;
      post({action:"resetpw",username:uname}).then(function(r){ card.querySelector(".tp").textContent="Temporary password: "+r.temp; })
        .catch(function(){ alert("Could not reset. Reload and try again."); });
    };
    card.querySelector(".no").onclick=function(){
      if(!confirm("Remove "+uname+"? This deletes their account and signs them out.")) return;
      post({action:"removeuser",username:uname}).then(function(){ card.remove(); })
        .catch(function(){ alert("Could not remove. Reload and try again."); });
    };
    return;
  }
  function act(action){
    post({action:action,url:card.dataset.url}).then(function(){ card.remove(); })
      .catch(function(){ alert("That did not work. Reload and try again."); });
  }
  var ok=card.querySelector(".ok"); if(ok) ok.onclick=function(){act(kind==="memberpending"?"approvemember":"approve")};
  card.querySelector(".no").onclick=function(){act(kind==="pending"?"delete":kind==="memberpending"?"deletememberpending":kind==="product"?"deleteproduct":kind==="order"?"deleteorder":kind==="invite"?"deleteinvite":"deletemember")};
});
</script></body></html>`);
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== invite =====
__mods["invite"] = (function (module, exports, require) {
// POST /api/invite  {email, website}
// Saves the invite request so it shows on your admin page. If RESEND_API_KEY and
// INVITE_TO_EMAIL are set, it is also emailed to you (optional).

const { put } = require("@vercel/blob");
const { jsonBody, limited, clientIp } = require("./_auth");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const body = jsonBody(req);
  const email = String(body.email || "").trim();

  // Spam trap: real people never fill this hidden field. Pretend success.
  if (body.website) return res.status(200).json({ ok: true });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (limited("invite:" + clientIp(req), 5, 10 * 60 * 1000)) {
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }

  let saved = false;
  try {
    await put("invites/i.json", JSON.stringify({ email, at: new Date().toISOString() }), {
      access: "public", contentType: "application/json", addRandomSuffix: true,
    });
    saved = true;
  } catch (e) { /* try email below */ }

  let emailed = false;
  const key = process.env.RESEND_API_KEY;
  const to = process.env.INVITE_TO_EMAIL;
  if (key && to) {
    try {
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: process.env.INVITE_FROM_EMAIL || "Orbweave <onboarding@resend.dev>",
          to: [to],
          reply_to: email,
          subject: "New Orbweave invite request",
          text: `Invite request from: ${email}\n\nCreate a code on your admin page and email it to them, then delete the request.`,
        }),
      });
      emailed = r.ok;
    } catch (e) { /* ignore */ }
  }

  if (!saved && !emailed) return res.status(502).json({ error: "Could not send request." });
  return res.status(200).json({ ok: true });
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== order =====
__mods["order"] = (function (module, exports, require) {
// POST /api/order  {product, name, contact, message, website}
// A visitor taps "I want this" on a product. The request is saved for your admin page
// and, if RESEND_API_KEY and INVITE_TO_EMAIL are set, also emailed to you.

const { put } = require("@vercel/blob");
const { jsonBody, limited, clientIp } = require("./_auth");

function clean(s, max) {
  return String(s == null ? "" : s).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, max);
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const b = jsonBody(req);

  // Spam trap: real people never fill this hidden field. Pretend success.
  if (b.website) return res.status(200).json({ ok: true });

  if (limited("order:" + clientIp(req), 5, 10 * 60 * 1000)) {
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }

  const product = clean(b.product, 80);
  const name = clean(b.name, 80);
  const contact = clean(b.contact, 120);
  const message = clean(b.message, 500);
  if (!name) return res.status(400).json({ error: "Enter your name." });
  if (contact.length < 3) return res.status(400).json({ error: "Enter an email or phone number so we can reply." });

  const order = { product, name, contact, message, at: new Date().toISOString() };

  try {
    await put("orders/o.json", JSON.stringify(order), { access: "public", contentType: "application/json", addRandomSuffix: true });
  } catch (e) {
    return res.status(500).json({ error: "Could not send your request." });
  }

  // Optional email notification. A failure here does not fail the request.
  const key = process.env.RESEND_API_KEY;
  const to = process.env.INVITE_TO_EMAIL;
  if (key && to) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: process.env.INVITE_FROM_EMAIL || "Orbweave <onboarding@resend.dev>",
          to: [to],
          subject: `New request: ${product || "product"}`,
          text: `Product: ${product}\nName: ${name}\nContact: ${contact}\n\n${message}`,
        }),
      });
    } catch (e) { /* ignore */ }
  }

  return res.status(200).json({ ok: true });
};

return module.exports;
})({ exports: {} }, {}, __req);

const __routes = {
  account: __mods.account, messages: __mods.messages, members: __mods.members, "member-image": __mods["member-image"],
  products: __mods.products, upload: __mods.upload, wall: __mods.wall, admin: __mods.admin,
  invite: __mods.invite, order: __mods.order,
};
module.exports = async function handler(req, res) {
  const route = String((req.query && req.query.route) || "").toLowerCase().replace(/[^a-z-]/g, "");
  const h = __routes[route];
  if (!h) return res.status(404).json({ error: "Not found" });
  return h(req, res);
};
