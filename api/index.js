// Orbweave: one function that serves every /api/<name> address.
require("@vercel/blob"); // static require so Vercel installs and bundles the storage library
const __real = require;
const __mods = {};
function __req(name) {
  if (name.indexOf("./") === 0) return __mods[name.slice(2)];
  return __real(name);
}

// ===== _util =====
__mods["_util"] = (function (module, exports, require) {
// Shared helpers (the leading underscore stops Vercel from exposing this file as a URL).

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

// Light per-instance limiter. For strong limits, add a Vercel Firewall rate-limit rule as well.
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

module.exports = { readBody, jsonBody, limited, clientIp };

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

// ===== _lines =====
__mods["_lines"] = (function (module, exports, require) {
// Shared helpers for turning a cart into trusted order lines (underscore = not a public URL).
// Names and prices are always looked up from YOUR product list on the server,
// so nothing the customer's browser says about prices is trusted.

const { listProducts } = require("./_products");

function clean(s, max) {
  return String(s == null ? "" : s).replace(/\r/g, "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").trim().slice(0, max);
}
function parsePrice(p) {
  const m = String(p || "").replace(/,/g, "").match(/(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : null;
}
function symbolOf(p) {
  const m = String(p || "").trim().match(/^[^\d\s.,-]+/);
  return m ? m[0] : "";
}

// Returns e.g. "$37.50" when every line has a usable price in the same currency, else "".
function computeTotal(lines) {
  if (!lines.length) return "";
  let sum = 0;
  let sym = null;
  for (const l of lines) {
    const n = parsePrice(l.price);
    if (n === null) return "";
    const s = symbolOf(l.price);
    if (sym === null) sym = s; else if (sym !== s) return "";
    sum += n * l.qty;
  }
  return sym + (sym.length > 1 ? " " : "") + sum.toFixed(2);
}

// items: [{ id, qty, name }]  ->  [{ name, price, qty, image, note? }]
async function linesFromItems(items) {
  let byId = new Map();
  try { for (const p of await listProducts(200)) byId.set(p.image, p); } catch (e) { byId = new Map(); }
  const lines = [];
  for (const it of (Array.isArray(items) ? items : []).slice(0, 20)) {
    const qty = Math.floor(Number(it && it.qty));
    if (!it || !(qty >= 1)) continue;
    const p = byId.get(String(it.id || ""));
    lines.push(p
      ? { name: clean(p.name, 80), price: clean(p.price, 30), qty: Math.min(qty, 99), image: p.image }
      : { name: clean(it.name, 80) || "Item", price: "", qty: Math.min(qty, 99), image: "", note: "no longer listed" });
  }
  return lines;
}

module.exports = { clean, parsePrice, symbolOf, computeTotal, linesFromItems };

return module.exports;
})({ exports: {} }, {}, __req);

// ===== _stripe =====
__mods["_stripe"] = (function (module, exports, require) {
// Talks to Stripe over HTTPS (no extra package needed). Underscore = not a public URL.
// Needs the environment variable STRIPE_SECRET_KEY (starts with sk_test_ or sk_live_).
// The key is only ever used here, on the server, and is never sent to the browser or put in errors.

function enabled() {
  return /^(sk|rk)_(test|live)_/.test(String(process.env.STRIPE_SECRET_KEY || ""));
}

// Stripe wants nested form fields: a[b][0][c]=value
function encode(obj) {
  const out = [];
  (function walk(v, prefix) {
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, prefix + "[" + i + "]"));
    else if (typeof v === "object") Object.keys(v).forEach((k) => walk(v[k], prefix ? prefix + "[" + k + "]" : k));
    else out.push(encodeURIComponent(prefix) + "=" + encodeURIComponent(String(v)));
  })(obj, "");
  return out.join("&");
}

async function stripe(method, path, params) {
  if (!enabled()) throw Object.assign(new Error("Stripe is not set up"), { code: "NOSTRIPE" });
  const opts = { method, headers: { Authorization: "Bearer " + process.env.STRIPE_SECRET_KEY } };
  let url = "https://api.stripe.com" + path;
  if (params) {
    if (method === "GET") url += "?" + encode(params);
    else { opts.body = encode(params); opts.headers["Content-Type"] = "application/x-www-form-urlencoded"; }
  }
  const r = await fetch(url, opts);
  let d = {};
  try { d = await r.json(); } catch (e) { /* ignore */ }
  if (!r.ok) {
    const err = new Error((d && d.error && d.error.message) || "Stripe error");
    err.stripe = true; err.status = r.status;
    throw err;
  }
  return d;
}

module.exports = { enabled, encode, stripe };

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
//   1. Read "I want this" requests from visitors, then delete them when you've replied
//   2. Post a product (do this every day) and delete old ones
//   3. Post pictures to the wall (only you can) and take them down
//
// Env vars: ADMIN_KEY (16+ characters), BLOB_READ_WRITE_TOKEN (added by Vercel Blob)
// Optional: RESEND_API_KEY + INVITE_TO_EMAIL to also get each request by email.

const { list, copy, del, put } = require("@vercel/blob");
const crypto = require("crypto");
const { jsonBody } = require("./_util");
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
    const b = jsonBody(req);
    const { action, url } = b;
    try {
      if (action === "approve" && isBlobUrlUnder(url, "pending")) {
        await copy(url, "approved/pic.jpg", { access: "public", addRandomSuffix: true });
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "delete" && isBlobUrlUnder(url, "pending")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "deleteapproved" && isBlobUrlUnder(url, "approved")) {
        await del(url);
        return res.status(200).json({ ok: true });
      }
      if (action === "addwall") {
        const raw = String(b.image || "").replace(/^data:image\/jpeg;base64,/, "");
        const buf = Buffer.from(raw, "base64");
        if (buf.length < 4 || buf.length > 2 * 1024 * 1024 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
          return res.status(400).json({ error: "Add a picture (JPEG, up to 2 MB)." });
        }
        await put("approved/pic.jpg", buf, { access: "public", contentType: "image/jpeg", addRandomSuffix: true });
        return res.status(200).json({ ok: true });
      }
      if (action === "addproduct") {
        const name = cleanText(b.name, 80);
        const desc = cleanText(b.desc, 400);
        const price = cleanText(b.price, 30);
        const link = cleanText(b.link, 300);
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
  const approved = (await list({ prefix: "approved/", limit: 200 })).blobs;
  approved.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
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

  const orderCard = (o) => {
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(o.contact || "");
    const contact = isEmail ? `<a href="mailto:${esc(o.contact)}">${esc(o.contact)}</a>` : esc(o.contact);
    const items = Array.isArray(o.items) && o.items.length
      ? "<ul style=\"margin:6px 0 0;padding-left:18px\">" + o.items.map((l) =>
          "<li>" + esc(l.qty) + " &times; " + esc(l.name) + (l.price ? " (" + esc(l.price) + ")" : "") + (l.note ? " <i>[" + esc(l.note) + "]</i>" : "") + "</li>").join("") + "</ul>"
      : "";
    return `<div class="c" data-url="${esc(o.id)}" data-kind="order">
      <div>${o.paid ? '<span style="background:#2a7a3b;color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700">PAID BY CARD</span> ' : ""}<strong>${items ? "Order" : esc(o.product || "Product")}</strong>${o.total ? " &middot; " + esc(o.total) : ""}<br><small>${esc(String(o.at || "").slice(0, 16).replace("T", " "))} UTC</small>${items}</div>
      <p><b>${esc(o.name)}</b><br>${contact}</p>
      ${o.address ? "<p><b>Delivery:</b> " + esc(o.address) + "</p>" : ""}
      <p>${esc(o.message) || "<i>No note</i>"}</p>
      <div><button class="no">Delete</button></div>
    </div>`;
  };

  const productCard = (p) => `<div class="c" data-url="${esc(p.id)}" data-kind="product">
      <img src="${esc(p.image)}" alt="${esc(p.name)}" loading="lazy">
      <div><strong>${esc(p.name)}</strong>${p.price ? " &middot; " + esc(p.price) : ""}<br><small>${esc(String(p.postedAt).slice(0, 10))}</small></div>
      <div><button class="no">Delete</button></div>
    </div>`;

  const card = (b, kind) => `<div class="c" data-url="${esc(b.url)}" data-kind="${kind}">
      <img src="${esc(b.url)}" alt="Picture to review" loading="lazy">
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
  button{font:inherit;padding:9px 14px;margin:10px 8px 0 0;border-radius:8px;border:0;cursor:pointer;color:#fff;background:#3a3fe0}
  .ok{background:#2a7a3b}.no{background:#b3361f}
  input[type=text],textarea{font:inherit;width:100%;padding:9px 10px;border-radius:8px;border:1px solid #ccd;margin-top:4px}
  label{font-weight:600;display:block}
  .box{background:#fff;border:1px solid #ccd;border-radius:12px;padding:16px}
</style></head><body>
<h1>Orbweave admin</h1>

<h2>Orders (${orders.length})</h2>
<p>Orders from the cart. Ones marked PAID BY CARD are already paid (see Stripe for the money). Others still need payment arranged. Contact each customer to agree delivery, then delete the order when you're done so their details don't pile up. Prices come from your product list, not from the customer's phone.</p>
<div class="g">${orders.map(orderCard).join("") || "<p>No requests yet.</p>"}</div>

<h2>Post a product</h2>
<div class="box">
  <p>Fill this in and press Post. It shows at the top of the home page (allow up to a minute). Come back each day to add the next one.</p>
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

<h2>Post a picture to the wall</h2>
<div class="box">
  <p>Only you can post here. The picture shows on the wall right away (allow up to a minute). Location and camera details are removed from the picture before it uploads.</p>
  <form id="wf" style="display:grid;gap:10px;max-width:520px">
    <label>Picture <input type="file" id="wfImg" accept="image/jpeg,image/png,image/webp"></label>
    <img id="wfPrev" alt="Preview" style="max-width:200px;display:none">
    <div><button type="submit" id="wfBtn">Post to the wall</button></div>
    <div id="wfMsg" role="status"></div>
  </form>
</div>

${pending.length ? `<h2>Old pictures from visitors (${pending.length})</h2>
<p>Left over from when visitors could upload. Delete them, or approve any you want to keep on the wall.</p>
<div class="g">${pending.map((b) => card(b, "pending")).join("")}</div>` : ""}

<h2>Pictures on the wall (${approved.length})</h2>
<p>These are showing to visitors now. Delete one to take it down.</p>
<div class="g">${approved.map((b) => card(b, "approved")).join("") || "<p>No pictures on the wall yet.</p>"}</div>

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
var wfBlob=null;
document.getElementById("wfImg").onchange=function(){
  var f=this.files[0]; wfBlob=null; document.getElementById("wfPrev").style.display="none"; if(!f) return;
  var url=URL.createObjectURL(f), img=new Image();
  img.onload=function(){
    var s=Math.min(1,1600/Math.max(img.naturalWidth,img.naturalHeight));
    var c=document.createElement("canvas"); c.width=Math.round(img.naturalWidth*s); c.height=Math.round(img.naturalHeight*s);
    var x=c.getContext("2d"); x.fillStyle="#fff"; x.fillRect(0,0,c.width,c.height); x.drawImage(img,0,0,c.width,c.height);
    c.toBlob(function(b){
      URL.revokeObjectURL(url);
      var rd=new FileReader(); rd.onload=function(){ wfBlob=rd.result; var p=document.getElementById("wfPrev"); p.src=rd.result; p.style.display="block"; }; rd.readAsDataURL(b);
    },"image/jpeg",0.85);
  };
  img.onerror=function(){ alert("Could not read that picture."); };
  img.src=url;
};
document.getElementById("wf").onsubmit=function(ev){
  ev.preventDefault();
  var msg=document.getElementById("wfMsg"); msg.textContent="";
  if(!wfBlob){ msg.textContent="Choose a picture first."; return; }
  var btn=document.getElementById("wfBtn"); btn.disabled=true;
  post({action:"addwall",image:wfBlob})
    .then(function(){ location.reload(); })
    .catch(function(e){ msg.textContent=e.message||"Could not post. Try again."; btn.disabled=false; });
};
document.querySelectorAll(".c").forEach(function(card){
  var kind=card.dataset.kind;
  function act(action){
    post({action:action,url:card.dataset.url}).then(function(){ card.remove(); })
      .catch(function(){ alert("That did not work. Reload and try again."); });
  }
  var ok=card.querySelector(".ok"); if(ok) ok.onclick=function(){act("approve")};
  card.querySelector(".no").onclick=function(){
    act(kind==="pending"?"delete":kind==="product"?"deleteproduct":kind==="order"?"deleteorder":"deleteapproved");
  };
});
</script></body></html>`);
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== order =====
__mods["order"] = (function (module, exports, require) {
// POST /api/order
//   Cart order:  { items: [{ id, qty }], name, contact, address, message, website }
//   Single item (older form): { product, name, contact, message, website }
//
// Saved for your admin page and, if RESEND_API_KEY and INVITE_TO_EMAIL are set, also emailed to you.
// Item names and prices are looked up from YOUR product list on the server, so what you see in the
// order is what you listed, whatever the customer's browser says.

const { put } = require("@vercel/blob");
const { jsonBody, limited, clientIp } = require("./_util");
const { listProducts } = require("./_products");

function clean(s, max) {
  return String(s == null ? "" : s).replace(/\r/g, "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").trim().slice(0, max);
}
function parsePrice(p) {
  const m = String(p || "").replace(/,/g, "").match(/(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : null;
}
function symbolOf(p) {
  const m = String(p || "").trim().match(/^[^\d\s.,-]+/);
  return m ? m[0] : "";
}

// Returns e.g. "$37.50" when every line has a usable price in the same currency, else "".
function computeTotal(lines) {
  if (!lines.length) return "";
  let sum = 0;
  let sym = null;
  for (const l of lines) {
    const n = parsePrice(l.price);
    if (n === null) return "";
    const s = symbolOf(l.price);
    if (sym === null) sym = s; else if (sym !== s) return "";
    sum += n * l.qty;
  }
  return sym + (sym.length > 1 ? " " : "") + sum.toFixed(2);
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

  const name = clean(b.name, 80);
  const contact = clean(b.contact, 120);
  const address = clean(b.address, 200);
  const message = clean(b.message, 500);
  if (!name) return res.status(400).json({ error: "Enter your name." });
  if (contact.length < 3) return res.status(400).json({ error: "Enter an email or phone number so we can reply." });

  let lines = [];
  if (Array.isArray(b.items)) {
    let byId = new Map();
    try { for (const p of await listProducts(200)) byId.set(p.image, p); } catch (e) { byId = new Map(); }
    for (const it of b.items.slice(0, 20)) {
      const qty = Math.floor(Number(it && it.qty));
      if (!it || !(qty >= 1)) continue;
      const p = byId.get(String(it.id || ""));
      lines.push(p
        ? { name: clean(p.name, 80), price: clean(p.price, 30), qty: Math.min(qty, 99) }
        : { name: clean(it.name, 80) || "Item", price: "", qty: Math.min(qty, 99), note: "no longer listed" });
    }
    if (!lines.length) return res.status(400).json({ error: "Your cart is empty." });
  } else {
    const product = clean(b.product, 80);
    if (!product) return res.status(400).json({ error: "Your cart is empty." });
    lines = [{ name: product, price: "", qty: 1 }];
  }

  const total = computeTotal(lines);
  const order = {
    items: lines,
    total,
    product: lines.map((l) => (l.qty > 1 ? l.qty + " x " : "") + l.name).join(", ").slice(0, 200),
    name, contact, address, message,
    at: new Date().toISOString(),
  };

  try {
    await put("orders/o.json", JSON.stringify(order), { access: "public", contentType: "application/json", addRandomSuffix: true });
  } catch (e) {
    return res.status(500).json({ error: "Could not send your order." });
  }

  // Optional email notification. A failure here does not fail the order.
  const key = process.env.RESEND_API_KEY;
  const to = process.env.INVITE_TO_EMAIL;
  if (key && to) {
    try {
      const itemText = lines.map((l) => `${l.qty} x ${l.name}${l.price ? " (" + l.price + ")" : ""}${l.note ? " [" + l.note + "]" : ""}`).join("\n");
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: process.env.INVITE_FROM_EMAIL || "Orbweave <onboarding@resend.dev>",
          to: [to],
          subject: `New order: ${lines.length} item${lines.length > 1 ? "s" : ""}${total ? " (" + total + ")" : ""}`,
          text: `${itemText}\n\n${total ? "Total: " + total + "\n\n" : ""}Name: ${name}\nContact: ${contact}\n${address ? "Delivery: " + address + "\n" : ""}\n${message}`,
        }),
      });
    } catch (e) { /* ignore */ }
  }

  return res.status(200).json({ ok: true });
};

return module.exports;
})({ exports: {} }, {}, __req);

// ===== checkout =====
__mods["checkout"] = (function (module, exports, require) {
// POST /api/checkout  { items:[{id,qty,name}], name, contact, address, message, website }
//   -> { url }  (the Stripe page where the customer pays by card)
// GET  /api/checkout?session_id=cs_...   (the customer comes back here after paying)
//   -> { paid: true|false, total }  and, if paid, the order is saved for your admin page.
//
// Prices come from YOUR product list on the server, never from the customer's browser.
// Needs STRIPE_SECRET_KEY. Without it, card payment answers 503 and "Send order" still works.

const { put, list } = require("@vercel/blob");
const { jsonBody, limited, clientIp } = require("./_util");
const { clean, parsePrice, symbolOf, linesFromItems } = require("./_lines");
const { enabled, stripe } = require("./_stripe");

const SYMBOLS = {
  "$": "usd", "US$": "usd", "USD": "usd", "\u20ac": "eur", "EUR": "eur", "\u00a3": "gbp", "GBP": "gbp",
  "CAD": "cad", "C$": "cad", "CA$": "cad", "AUD": "aud", "A$": "aud",
  "XAF": "xaf", "FCFA": "xaf", "CFA": "xaf", "XOF": "xof",
};
const ZERO_DECIMAL = new Set(["xaf", "xof", "jpy", "krw", "vnd", "clp", "pyg", "ugx", "rwf", "kmf", "gnf", "djf", "xpf", "bif", "vuv"]);
const SHOW = { usd: "$", eur: "\u20ac", gbp: "\u00a3" };

function currencyOf(price) {
  const s = symbolOf(price).toUpperCase();
  if (SYMBOLS[s]) return SYMBOLS[s];
  const t = String(price || "").trim().match(/([A-Za-z]{3,4})$/);
  return t && SYMBOLS[t[1].toUpperCase()] ? SYMBOLS[t[1].toUpperCase()] : null;
}
function minor(amount, cur) { return ZERO_DECIMAL.has(cur) ? Math.round(amount) : Math.round(amount * 100); }
function major(units, cur) { return ZERO_DECIMAL.has(cur) ? units : units / 100; }
function money(units, cur) {
  const n = major(units, cur).toFixed(ZERO_DECIMAL.has(cur) ? 0 : 2);
  return SHOW[cur] ? SHOW[cur] + n : cur.toUpperCase() + " " + n;
}

async function create(req, res) {
  const b = jsonBody(req);
  if (b.website) return res.status(200).json({ ok: true });
  if (limited("checkout:" + clientIp(req), 10, 10 * 60 * 1000)) return res.status(429).json({ error: "Too many requests. Try again later." });
  if (!enabled()) return res.status(503).json({ error: "Card payments are not switched on yet." });

  const name = clean(b.name, 80), contact = clean(b.contact, 120), address = clean(b.address, 200), message = clean(b.message, 500);
  if (!name) return res.status(400).json({ error: "Enter your name." });
  if (contact.length < 3) return res.status(400).json({ error: "Enter an email or phone number so we can reach you." });

  const lines = await linesFromItems(b.items);
  if (!lines.length) return res.status(400).json({ error: "Your cart is empty." });
  if (lines.some((l) => l.note)) return res.status(400).json({ error: "An item in your cart is no longer for sale. Remove it and try again." });

  let cur = null;
  for (const l of lines) {
    const c = currencyOf(l.price), n = parsePrice(l.price);
    if (!c || n === null || !(n > 0)) return res.status(400).json({ error: "Card payment is not available for one of these items. Use Send order instead." });
    if (cur && cur !== c) return res.status(400).json({ error: "These items are priced in different currencies. Order them separately." });
    cur = c; l.unit = minor(n, c);
  }

  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "");
  if (!/^[a-z0-9.-]+(:\d+)?$/i.test(host)) return res.status(400).json({ error: "Bad request." });
  const origin = "https://" + host;
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact);

  const params = {
    mode: "payment",
    success_url: origin + "/?paid={CHECKOUT_SESSION_ID}",
    cancel_url: origin + "/?cancelled=1",
    line_items: lines.map((l) => ({
      quantity: l.qty,
      price_data: {
        currency: cur, unit_amount: l.unit,
        product_data: Object.assign({ name: l.name }, /^https:\/\//.test(l.image || "") ? { images: [l.image] } : {}),
      },
    })),
    metadata: { name, contact, address, message },
  };
  if (isEmail) params.customer_email = contact;

  try {
    const s = await stripe("POST", "/v1/checkout/sessions", params);
    if (!s.url || !/^https:\/\/checkout\.stripe\.com\//.test(s.url)) throw new Error("no url");
    return res.status(200).json({ url: s.url });
  } catch (e) {
    return res.status(502).json({ error: "Could not start the card payment. Try again, or use Send order." });
  }
}

async function confirm(req, res) {
  const id = String((req.query && req.query.session_id) || "");
  if (!/^cs_[A-Za-z0-9_]{10,200}$/.test(id)) return res.status(400).json({ error: "Bad request." });
  if (limited("confirm:" + clientIp(req), 30, 10 * 60 * 1000)) return res.status(429).json({ error: "Too many requests." });
  if (!enabled()) return res.status(503).json({ error: "Card payments are not switched on yet." });

  let s;
  try { s = await stripe("GET", "/v1/checkout/sessions/" + id, { expand: ["line_items"] }); }
  catch (e) { return res.status(502).json({ error: "Could not check the payment." }); }
  if (s.payment_status !== "paid") return res.status(200).json({ paid: false });

  const cur = String(s.currency || "usd").toLowerCase();
  const total = money(s.amount_total || 0, cur);
  const md = s.metadata || {};
  const items = ((s.line_items && s.line_items.data) || []).map((li) => ({
    name: clean(li.description, 80), qty: li.quantity,
    price: money(li.price && li.price.unit_amount != null ? li.price.unit_amount : Math.round((li.amount_total || 0) / (li.quantity || 1)), cur),
  }));
  const order = {
    items, total, paid: true, sessionId: id,
    product: items.map((l) => (l.qty > 1 ? l.qty + " x " : "") + l.name).join(", ").slice(0, 200),
    name: clean(md.name, 80), contact: clean(md.contact, 120), address: clean(md.address, 200), message: clean(md.message, 500),
    at: new Date().toISOString(),
  };

  let already = false;
  try { already = (await list({ prefix: "orders/paid-" + id, limit: 1 })).blobs.length > 0; } catch (e) { already = false; }
  if (!already) {
    try {
      await put("orders/paid-" + id + ".json", JSON.stringify(order), { access: "public", contentType: "application/json", addRandomSuffix: false, allowOverwrite: true });
    } catch (e) { return res.status(500).json({ error: "Payment received but the order could not be saved. Check your Stripe dashboard." }); }

    const key = process.env.RESEND_API_KEY, to = process.env.INVITE_TO_EMAIL;
    if (key && to) {
      try {
        const itemText = items.map((l) => l.qty + " x " + l.name + " (" + l.price + ")").join("\n");
        await fetch("https://api.resend.com/emails", {
          method: "POST", headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
          body: JSON.stringify({
            from: process.env.INVITE_FROM_EMAIL || "Orbweave <onboarding@resend.dev>", to: [to],
            subject: "PAID order " + total,
            text: itemText + "\n\nPaid by card: " + total + "\n\nName: " + order.name + "\nContact: " + order.contact + "\n" + (order.address ? "Delivery: " + order.address + "\n" : "") + "\n" + order.message,
          }),
        });
      } catch (e) { /* ignore */ }
    }
  }
  return res.status(200).json({ paid: true, total });
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "POST") return create(req, res);
  if (req.method === "GET") return confirm(req, res);
  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
};

return module.exports;
})({ exports: {} }, {}, __req);

const __routes = {
  products: __mods.products, wall: __mods.wall, admin: __mods.admin, order: __mods.order, checkout: __mods.checkout,
};
module.exports = async function handler(req, res) {
  const route = String((req.query && req.query.route) || "").toLowerCase().replace(/[^a-z-]/g, "");
  const h = __routes[route];
  if (!h) return res.status(404).json({ error: "Not found" });
  return h(req, res);
};
