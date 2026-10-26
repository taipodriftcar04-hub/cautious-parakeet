// Orbweave: one function that serves every /api/<name> address.// Orbweave.
require("@vercel/blob");
// (Combined into a single file so it can be uploaded easily from a phone.)
const __real = require;
const __mods = {};
function __req(name) {
  if (name === "./_auth") return __mods._auth;
  if (name === "./_products") return __mods._products;
  return __real(name);
}

// ===== _auth =====
__mods["_auth"] = (function (module, exports, require) {
// Shared helpers (the leading underscore stops Vercel from exposing this file as a URL).
//
// Invite codes are signed, so they need no database:  abc234-0kq2-1a2b3c4d5e6f
//   id (6 chars) - expiry day (base36) - signature
// Member sessions are signed cookies that last 30 days.
//
// Required env var: SESSION_SECRET (random string, 32+ characters)
// Optional env var: REVOKED_CODES (comma-separated code ids to block, e.g. "abc234,xyz789")

const crypto = require("crypto");

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

function sessionCookie(id) {
  const payload = Buffer.from(JSON.stringify({ id, exp: Date.now() + 30 * DAY })).toString("base64url");
  const token = payload + "." + hmac("sess:" + payload);
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${30 * 86400}`;
}
function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

function readSession(req) {
  try {
    const header = req.headers.cookie || "";
    const pair = header.split(";").map((s) => s.trim()).find((s) => s.startsWith(COOKIE + "="));
    if (!pair) return null;
    const token = pair.slice(COOKIE.length + 1);
    const [payload, sig] = token.split(".");
    if (!payload || !sig || !safeEq(hmac("sess:" + payload), sig)) return null;
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (!data.exp || data.exp < Date.now()) return null;
    if (revoked().includes(String(data.id))) return null;
    return { id: data.id };
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

// ===== join =====
__mods["join"] = (function (module, exports, require) {
// POST /api/join  {code}     -> checks the invite code and signs the member in
// POST /api/join  {logout:true} -> signs out

const { checkCode, sessionCookie, clearCookie, jsonBody, limited, clientIp } = require("./_auth");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const body = jsonBody(req);

  if (body.logout) {
    res.setHeader("Set-Cookie", clearCookie());
    return res.status(200).json({ ok: true });
  }

  // Slow down guessing: 10 tries per 10 minutes per visitor.
  if (limited("join:" + clientIp(req), 10, 10 * 60 * 1000)) {
    return res.status(429).json({ error: "Too many tries. Wait a few minutes." });
  }

  try {
    const c = checkCode(body.code);
    if (!c) return res.status(401).json({ error: "That code is not valid or has expired." });
    res.setHeader("Set-Cookie", sessionCookie(c.id));
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: "Sign-in is not set up yet." });
  }
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== members =====
__mods["members"] = (function (module, exports, require) {
// Members only (needs the sign-in cookie from /api/join).
// GET  /api/members  -> { images: [ "/api/member-image?u=...", ... ] } newest first
// POST /api/members  (raw JPEG bytes) -> saves a private picture

const { put, list } = require("@vercel/blob");
const { readSession, readBody, limited } = require("./_auth");

const MAX_BYTES = 2 * 1024 * 1024;

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: "Sign in with an invite code." });

  if (req.method === "GET") {
    try {
      const { blobs } = await list({ prefix: "members/", limit: 200 });
      blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
      return res.status(200).json({
        images: blobs.map((b) => "/api/member-image?u=" + encodeURIComponent(b.url)),
      });
    } catch (e) {
      return res.status(200).json({ images: [] });
    }
  }

  if (req.method === "POST") {
    if (limited("mem:" + session.id, 20, 10 * 60 * 1000)) {
      return res.status(429).json({ error: "Too many uploads" });
    }
    try {
      const buf = await readBody(req, MAX_BYTES);
      if (buf.length > MAX_BYTES) return res.status(413).json({ error: "Too large" });
      if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
        return res.status(400).json({ error: "Not a JPEG" });
      }
      await put("members/pic.jpg", buf, { access: "public", contentType: "image/jpeg", addRandomSuffix: true });
      return res.status(200).json({ ok: true });
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
  if (!readSession(req)) return res.status(401).end();

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
    const { action, url, days } = jsonBody(req);
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
  const members = (await list({ prefix: "members/", limit: 200 })).blobs;
  members.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  const key = encodeURIComponent(req.query.key);
  let products = [];
  try { products = await listProducts(60); } catch (e) { products = []; }

  const productCard = (p) => `<div class="c" data-url="${esc(p.id)}" data-kind="product">
      <img src="${esc(p.image)}" alt="${esc(p.name)}" loading="lazy">
      <div><strong>${esc(p.name)}</strong>${p.price ? " &middot; " + esc(p.price) : ""}<br><small>${esc(String(p.postedAt).slice(0, 10))}</small></div>
      <div><button class="no">Delete</button></div>
    </div>`;

  const card = (b, kind) => `<div class="c" data-url="${b.url}" data-kind="${kind}">
      <img src="${b.url}" alt="Picture to review" loading="lazy">
      <div>${kind === "pending" ? '<button class="ok">Approve</button>' : ""}<button class="no">Delete</button></div>
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
  <p>Make a code, then email it to the person you are inviting. Each code works for many sign-ins until it expires, so share it with one person only. To block a code early, add its first 6 letters to the REVOKED_CODES setting in Vercel and redeploy.</p>
  <label>Valid for <select id="days"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option></select></label>
  <button id="mk">Create code</button>
  <div id="codes" aria-live="polite"></div>
</div>

<h2>Wall pictures waiting for review (${pending.length})</h2>
<p>Look at each picture at full size before approving. Delete anything unsafe, illegal, or showing people who may not have agreed.</p>
<div class="g">${pending.map((b) => card(b, "pending")).join("") || "<p>Nothing waiting for review.</p>"}</div>

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
  function act(action){
    post({action:action,url:card.dataset.url}).then(function(){ card.remove(); })
      .catch(function(){ alert("That did not work. Reload and try again."); });
  }
  var ok=card.querySelector(".ok"); if(ok) ok.onclick=function(){act("approve")};
  card.querySelector(".no").onclick=function(){act(kind==="pending"?"delete":kind==="product"?"deleteproduct":"deletemember")};
});
</script></body></html>`);
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== invite =====
__mods["invite"] = (function (module, exports, require) {
// Vercel serverless function: receives an invite request and emails it to you.
// Nothing is stored on a server or database; the request lives only in your inbox.
//
// Required environment variables (Vercel > Project > Settings > Environment Variables):
//   RESEND_API_KEY   your key from resend.com
//   INVITE_TO_EMAIL  the inbox that should receive requests
// Optional:
//   INVITE_FROM_EMAIL  defaults to Resend's test sender (only delivers to your own Resend account email)

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const body = typeof req.body === "string" ? safeParse(req.body) : req.body || {};
  const email = String(body.email || "").trim();

  // Spam trap: real people never fill this hidden field. Pretend success.
  if (body.website) return res.status(200).json({ ok: true });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  const key = process.env.RESEND_API_KEY;
  const to = process.env.INVITE_TO_EMAIL;
  if (!key || !to) {
    return res.status(500).json({ error: "Server is not configured." });
  }

  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.INVITE_FROM_EMAIL || "Orbweave <onboarding@resend.dev>",
        to: [to],
        reply_to: email,
        subject: "New Orbweave invite request",
        text: `Invite request from: ${email}\n\nReply to this email to send their invite, then delete this message.`,
      }),
    });
    if (!r.ok) return res.status(502).json({ error: "Could not send request." });
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(502).json({ error: "Could not send request." });
  }
};

function safeParse(s) {
  try { return JSON.parse(s); } catch (e) { return {}; }
}

return module.exports;
})({ exports: {} }, {}, __req);

const __routes = {
  join: __mods.join, members: __mods.members, "member-image": __mods["member-image"],
  products: __mods.products, upload: __mods.upload, wall: __mods.wall, admin: __mods.admin, invite: __mods.invite,
};
module.exports = async function handler(req, res) {
  const route = String((req.query && req.query.route) || "").toLowerCase().replace(/[^a-z-]/g, "");
  const h = __routes[route];
  if (!h) return res.status(404).json({ error: "Not found" });
  return h(req, res);
};
