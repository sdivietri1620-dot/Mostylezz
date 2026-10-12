'use strict';
/*
 * MoStyles server: serves the start page and a simple web proxy at /go?u=<url>.
 * No dependencies. Needs Node 18+.
 *
 * Env vars (all optional):
 *   PORT                  port to listen on (hosts set this for you)
 *   ACCESS_PASSWORD       if set, the whole site asks for this password (any username)
 *   TRUST_PROXY           "1" (default) reads the visitor IP from X-Forwarded-For; set "0" if not behind a host proxy
 *   ALLOW_PRIVATE_NETWORK "1" lets the proxy reach private/local addresses. TESTING ONLY, never in production.
 */
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const gzipAsync = promisify(zlib.gzip), gunzipAsync = promisify(zlib.gunzip), brAsync = promisify(zlib.brotliDecompress), inflateAsync = promisify(zlib.inflate);
const { URL } = require('url');

const PORT = +process.env.PORT || 3000;
const PASSWORD = process.env.ACCESS_PASSWORD || '';
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_NETWORK === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');

const MAX_REQ_BODY = 5 * 1024 * 1024;     // form posts
const MAX_REWRITE = 15 * 1024 * 1024;     // html/css we rewrite in memory
const MAX_STREAM = 150 * 1024 * 1024;     // anything else we stream through
const TIMEOUT_MS = 20000;
const RATE_LIMIT = 900;                   // requests per IP per minute
const P = '/go?u=';
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });
const clientGzip = req => /\bgzip\b/.test(req.headers['accept-encoding'] || '');
async function sendBody(res, status, headers, body, gz){
  let buf = Buffer.from(body, 'utf8');
  if(gz && buf.length > 1024){ buf = await gzipAsync(buf, { level: 4 }); headers['content-encoding'] = 'gzip'; }
  headers['vary'] = 'Accept-Encoding'; headers['content-length'] = buf.length;
  res.writeHead(status, headers); res.end(buf);
}
async function inflateBody(buf, enc){
  if(enc === 'gzip' || enc === 'x-gzip') return gunzipAsync(buf, { maxOutputLength: MAX_REWRITE * 3 });
  if(enc === 'br') return brAsync(buf, { maxOutputLength: MAX_REWRITE * 3 });
  if(enc === 'deflate') return inflateAsync(buf, { maxOutputLength: MAX_REWRITE * 3 });
  return buf;
}

/* ---------- helpers ---------- */
const enc = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function send(res, code, msg){
  if(res.headersSent){ res.end(); return; }
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
  res.end(msg);
}
function collect(stream, max){
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    stream.on('data', c => { n += c.length; if(n > max){ stream.destroy(); reject(new Error('too large')); return; } chunks.push(c); });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

/* ---------- per-visitor cookie jar (kept in memory only) ---------- */
const jars = new Map();
const MAX_JARS = 500, MAX_COOKIES = 400;
function getSid(req){ const m = /(?:^|;\s*)msid=([a-f0-9]{32})/.exec(req.headers.cookie || ''); return m ? m[1] : null; }
function ensureJar(req){
  let sid = getSid(req), fresh = false;
  if(!sid || !jars.has(sid)){
    if(!sid) sid = crypto.randomBytes(16).toString('hex');
    fresh = true; jars.set(sid, { t: Date.now(), cookies: new Map() });
    while(jars.size > MAX_JARS) jars.delete(jars.keys().next().value);
  }
  const jar = jars.get(sid); jar.t = Date.now();
  return { sid, jar, fresh };
}
function sidCookie(req, sid){
  const secure = req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
  return 'msid=' + sid + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000' + (secure ? '; Secure' : '');
}
setInterval(() => { const old = Date.now() - 30 * 86400000; for(const [k, v] of jars) if(v.t < old) jars.delete(k); }, 3600000).unref();

function parseSetCookie(str, target){
  const parts = String(str).split(';'), nv = parts.shift(), i = nv.indexOf('=');
  if(i < 1) return null;
  const c = { name: nv.slice(0, i).trim(), value: nv.slice(i + 1).trim(), domain: target.hostname.toLowerCase(), path: '', secure: false, httpOnly: false, expires: 0, hostOnly: true };
  let maxAge = null;
  for(const a of parts){
    const j = a.indexOf('='), key = (j < 0 ? a : a.slice(0, j)).trim().toLowerCase(), val = j < 0 ? '' : a.slice(j + 1).trim();
    if(key === 'domain' && val){ c.domain = val.replace(/^\./, '').toLowerCase(); c.hostOnly = false; }
    else if(key === 'path' && val[0] === '/') c.path = val;
    else if(key === 'expires'){ const t = Date.parse(val); if(!isNaN(t)) c.expires = t; }
    else if(key === 'max-age'){ const n = parseInt(val, 10); if(!isNaN(n)) maxAge = n; }
    else if(key === 'secure') c.secure = true;
    else if(key === 'httponly') c.httpOnly = true;
  }
  if(maxAge !== null) c.expires = maxAge <= 0 ? 1 : Date.now() + maxAge * 1000;
  if(!c.path){ const p = target.pathname, k = p.lastIndexOf('/'); c.path = k > 0 ? p.slice(0, k) : '/'; }
  const h = target.hostname.toLowerCase();
  if(!c.hostOnly && !(h === c.domain || h.endsWith('.' + c.domain))) return null;
  if(!c.hostOnly && !c.domain.includes('.')) return null;
  return c;
}
function storeCookie(jar, c){
  const key = c.name + '|' + c.domain + '|' + c.path;
  if(c.expires && c.expires <= Date.now()){ jar.cookies.delete(key); return; }
  jar.cookies.delete(key); jar.cookies.set(key, c);
  while(jar.cookies.size > MAX_COOKIES) jar.cookies.delete(jar.cookies.keys().next().value);
}
function cookiesFor(jar, target, forScript){
  const h = target.hostname.toLowerCase(), now = Date.now(), p = target.pathname || '/', out = [];
  for(const [k, c] of jar.cookies){
    if(c.expires && c.expires <= now){ jar.cookies.delete(k); continue; }
    if(c.hostOnly ? h !== c.domain : !(h === c.domain || h.endsWith('.' + c.domain))) continue;
    if(!(c.path === '/' || p === c.path || p.startsWith(c.path.endsWith('/') ? c.path : c.path + '/'))) continue;
    if(c.secure && target.protocol !== 'https:') continue;
    if(forScript && c.httpOnly) continue;
    out.push(c);
  }
  out.sort((a, b) => b.path.length - a.path.length);
  return out.map(c => c.name + '=' + c.value).join('; ');
}
function isOwnAuth(h){
  if(!PASSWORD || !String(h).startsWith('Basic ')) return false;
  return Buffer.from(String(h).slice(6), 'base64').toString().split(':').slice(1).join(':') === PASSWORD;
}

/* ---------- small in-memory cache for static assets ---------- */
const cache = new Map(); let cacheBytes = 0;
const CACHE_MAX = 40 * 1024 * 1024, CACHE_ITEM_MAX = 2 * 1024 * 1024;
function cacheGet(key){
  const e = cache.get(key); if(!e) return null;
  if(e.exp < Date.now()){ cacheBytes -= e.body.length; cache.delete(key); return null; }
  cache.delete(key); cache.set(key, e); return e;
}
function cachePut(key, e){
  if(e.body.length > CACHE_ITEM_MAX) return;
  while(cacheBytes + e.body.length > CACHE_MAX && cache.size){ const k = cache.keys().next().value; cacheBytes -= cache.get(k).body.length; cache.delete(k); }
  cache.set(key, e); cacheBytes += e.body.length;
}
function cacheTtl(h){
  const cc = String(h['cache-control'] || '').toLowerCase();
  if(!cc || /no-store|no-cache|private/.test(cc) || h['set-cookie'] || /cookie|\*/i.test(h.vary || '')) return 0;
  const m = /(?:^|[ ,])max-age=(\d+)/.exec(cc);
  return m ? Math.min(+m[1], 3600) * 1000 : 0;
}

/* ---------- SSRF protection ---------- */
function isPrivateIp(ip){
  if(net.isIPv4(ip)){
    const p = ip.split('.').map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) ||
      (p[0] === 192 && p[1] === 0 && p[2] === 0) || (p[0] === 198 && (p[1] === 18 || p[1] === 19)) || p[0] >= 224;
  }
  if(net.isIPv6(ip)){
    const l = ip.toLowerCase();
    if(l === '::' || l === '::1') return true;
    const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if(m) return isPrivateIp(m[1]);
    if(l.startsWith('::ffff:') || l.startsWith('64:ff9b')) return true;
    return /^(fc|fd|fe[89ab])/.test(l);
  }
  return true;
}
// Validates the resolved IP at connect time, so DNS tricks can't point us at internal addresses.
function safeLookup(hostname, options, cb){
  if(typeof options === 'function'){ cb = options; options = {}; }
  dns.lookup(hostname, Object.assign({}, options, { all: true }), (err, addrs) => {
    if(err) return cb(err);
    const ok = addrs.filter(a => ALLOW_PRIVATE || !isPrivateIp(a.address));
    if(!ok.length) return cb(new Error('Blocked address'));
    if(options && options.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}
function parseTarget(raw){
  let u; try{ u = new URL(raw); }catch(e){ return null; }
  if(u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  u.username = ''; u.password = '';
  const port = u.port ? +u.port : (u.protocol === 'https:' ? 443 : 80);
  if(!ALLOW_PRIVATE && ![80, 443, 8080, 8443].includes(port)) return null;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if(!ALLOW_PRIVATE && net.isIP(host) && isPrivateIp(host)) return null;
  return u;
}

/* ---------- auth + rate limit ---------- */
function authOk(req, res){
  if(!PASSWORD) return true;
  const h = req.headers.authorization || '';
  if(h.startsWith('Basic ')){
    const pw = Buffer.from(h.slice(6), 'base64').toString().split(':').slice(1).join(':');
    const a = Buffer.from(pw), b = Buffer.from(PASSWORD);
    if(a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  res.writeHead(401, { 'www-authenticate': 'Basic realm="MoStyles", charset="UTF-8"', 'content-type': 'text/plain' });
  res.end('Password required');
  return false;
}
const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
function rateOk(req, res){
  let ip = req.socket.remoteAddress || '?';
  if(TRUST_PROXY && req.headers['x-forwarded-for']) ip = String(req.headers['x-forwarded-for']).split(',')[0].trim();
  const n = (hits.get(ip) || 0) + 1; hits.set(ip, n);
  if(n > RATE_LIMIT){ send(res, 429, 'Slow down.'); return false; }
  return true;
}

/* ---------- rewriting ---------- */
function px(raw, base){
  raw = String(raw).trim().replace(/&amp;/g, '&');
  if(!raw || raw[0] === '#' || /^(data|javascript|mailto|tel|blob|about):/i.test(raw)) return null;
  try{
    const a = new URL(raw, base);
    if(a.protocol !== 'http:' && a.protocol !== 'https:') return null;
    return P + enc(a.href);
  }catch(e){ return null; }
}
function rewriteCss(css, base){
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => { const r = px(u, base); return r ? 'url(' + q + r + q + ')' : m; });
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => { const r = px(u, base); return r ? '@import ' + q + r + q : m; });
  return css;
}
function clientScript(base, cookies){
  const b = JSON.stringify(base).replace(/</g, '\\u003c');
  const ck = JSON.stringify(cookies || '').replace(/</g, '\\u003c');
  return String.raw`(function(){
var BASE=${b};
function px(u){
  try{
    if(u==null) return u;
    u=String(u);
    if(u.indexOf('/go?u=')===0) return u;
    if(/^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(u)) return u;
    var a=new URL(u,BASE);
    if(a.protocol!=='http:'&&a.protocol!=='https:') return u;
    if(a.origin===location.origin){
      if(a.pathname==='/go') return a.href;
      a=new URL(a.pathname+a.search+a.hash,BASE);
    }
    return '/go?u='+encodeURIComponent(a.href);
  }catch(e){return u;}
}
var _f=window.fetch;
if(_f) window.fetch=function(i,o){
  try{
    if(typeof i==='string'||(window.URL&&i instanceof URL)) i=px(i);
    else if(i&&i.url) i=new Request(px(i.url),i);
  }catch(e){}
  return _f.call(this,i,o);
};
var _o=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){ arguments[1]=px(u); return _o.apply(this,arguments); };
var CK=${ck};
if(_f){ try{ Object.defineProperty(Document.prototype,'cookie',{configurable:true,
get:function(){return CK;},
set:function(v){
  v=String(v);
  if(v.indexOf('=')<1) return;
  try{
    var nv=v.split(';')[0], i=nv.indexOf('='), name=nv.slice(0,i).trim(), val=nv.slice(i+1).trim();
    var ma=/max-age=\s*(-?\d+)/i.exec(v), ex=/expires=([^;]*)/i.exec(v);
    var gone=(ma&&+ma[1]<=0)||(!ma&&ex&&Date.parse(ex[1])<Date.now());
    var parts=CK?CK.split('; '):[];
    parts=parts.filter(function(p){return p.indexOf(name+'=')!==0;});
    if(!gone) parts.push(name+'='+val);
    CK=parts.join('; ');
  }catch(e){}
  try{ _f.call(window,'/__c?u='+encodeURIComponent(BASE),{method:'POST',body:v,credentials:'same-origin',keepalive:true,headers:{'content-type':'text/plain'}}); }catch(e){}
}}); }catch(e){} }
var _w=window.open;
window.open=function(u){ if(u) arguments[0]=px(u); return _w.apply(this,arguments); };
document.addEventListener('click',function(e){
  if(e.defaultPrevented||e.button!==0) return;
  var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;
  if(!a) return;
  var h=a.getAttribute('href'), p=px(h);
  if(p!==h) a.setAttribute('href',p);
},true);
document.addEventListener('submit',function(e){
  var f=e.target;
  if(!f||f.tagName!=='FORM') return;
  var raw=f.getAttribute('action');
  if(raw&&raw.indexOf('/go?u=')===0) return;
  var dest;
  try{ dest=new URL(raw||'',BASE); }catch(err){ return; }
  if((f.method||'get').toLowerCase()==='post'){ f.setAttribute('action','/go?u='+encodeURIComponent(dest.href)); return; }
  e.preventDefault();
  var qs=new URLSearchParams();
  new FormData(f).forEach(function(v,k){ if(typeof v==='string') qs.append(k,v); });
  dest.search=qs.toString();
  location.href='/go?u='+encodeURIComponent(dest.href);
},true);
})();`;
}
function rewriteHtml(html, base, cookies){
  html = html.replace(/<meta[^>]+http-equiv\s*=\s*["']?(?:content-security-policy|x-frame-options)[^>]*>/gi, '');
  html = html.replace(/<meta[^>]+name\s*=\s*["']?referrer["']?[^>]*>/gi, '');
  html = html.replace(/<base\b[^>]*>/gi, '');
  html = html.replace(/\s+integrity\s*=\s*("[^"]*"|'[^']*')/gi, '');
  html = html.replace(/(\s(?:href|src|poster|data-src|data-href)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi, (m, pre, d, s) => {
    const r = px(d !== undefined ? d : s, base); return r ? pre + '"' + r + '"' : m;
  });
  html = html.replace(/(\s(?:srcset|data-srcset)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi, (m, pre, d, s) => {
    const v = d !== undefined ? d : s;
    const out = v.split(',').map(part => {
      const t = part.trim(); if(!t) return t;
      const bits = t.split(/\s+/), r = px(bits[0], base);
      return (r || bits[0]) + (bits.length > 1 ? ' ' + bits.slice(1).join(' ') : '');
    }).join(', ');
    return pre + '"' + out + '"';
  });
  html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, c) => a + rewriteCss(css, base) + c);
  html = html.replace(/(\sstyle\s*=\s*)"([^"]*)"/gi, (m, pre, css) => pre + '"' + rewriteCss(css, base) + '"');
  html = html.replace(/(<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']\s*\d+\s*;\s*url=)([^"']+)/gi, (m, pre, u) => { const r = px(u, base); return pre + (r || u); });
  const inject = '<meta charset="utf-8"><meta name="referrer" content="same-origin"><script>' + clientScript(base, cookies) + '</script>';
  if(/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + inject);
  if(/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + inject);
  return inject + html;
}
function decode(buf, ct){
  const m = /charset=([^;\s]+)/i.exec(ct || '');
  let label = m ? m[1].replace(/['"]/g, '') : null;
  if(!label){ const mm = /<meta[^>]+charset=["']?([\w-]+)/i.exec(buf.slice(0, 2048).toString('latin1')); if(mm) label = mm[1]; }
  try{ return new TextDecoder(label || 'utf-8').decode(buf); }catch(e){ return buf.toString('utf8'); }
}

/* ---------- the proxy ---------- */
async function proxy(req, res, url){
  const target = parseTarget(url.searchParams.get('u') || '');
  if(!target) return send(res, 400, 'Bad or blocked address.');
  if(!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return send(res, 405, 'Method not allowed.');
  const { sid, jar, fresh } = ensureJar(req);
  if(fresh) res.setHeader('set-cookie', sidCookie(req, sid));
  let body = null;
  if(req.method !== 'GET' && req.method !== 'HEAD'){
    try{ body = await collect(req, MAX_REQ_BODY); }catch(e){ return send(res, 413, 'Request too large.'); }
  }
  const gz = clientGzip(req);
  const headers = {
    'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
    'accept': req.headers.accept || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': gz ? 'gzip' : 'identity'
  };
  ['range', 'if-none-match', 'if-modified-since', 'if-range'].forEach(h => { if(req.headers[h]) headers[h] = req.headers[h]; });
  Object.keys(req.headers).forEach(k => { if(/^x-/.test(k) && !/^x-(forwarded|real-ip|render|request-start|vercel|amzn)/.test(k)) headers[k] = req.headers[k]; });
  if(req.headers.authorization && !isOwnAuth(req.headers.authorization)) headers.authorization = req.headers.authorization;
  // tell the site which page the request came from (taken from our own Referer, never our host name)
  let pageUrl = null;
  try{ const r = new URL(req.headers.referer || ''); if(r.pathname === '/go') pageUrl = r.searchParams.get('u'); }catch(e){}
  if(pageUrl && parseTarget(pageUrl)){
    headers.referer = pageUrl;
    if(req.headers.origin) headers.origin = new URL(pageUrl).origin;
  } else if(req.headers.origin) headers.origin = target.origin;
  const ck = cookiesFor(jar, target, false);
  if(ck) headers.cookie = ck;
  if(body){ headers['content-length'] = body.length; headers['content-type'] = req.headers['content-type'] || 'application/x-www-form-urlencoded'; }

  const cacheable = req.method === 'GET' && !req.headers.range && !ck;
  const ckey = (gz ? '1|' : '0|') + target.href;
  if(cacheable){
    const hit = cacheGet(ckey);
    if(hit){ res.writeHead(200, Object.assign({}, hit.headers, { 'content-length': hit.body.length, 'x-cache': 'HIT' })); return res.end(hit.body); }
  }

  const lib = target.protocol === 'https:' ? https : http;
  const up = lib.request({
    protocol: target.protocol, hostname: target.hostname.replace(/^\[|\]$/g, ''), port: target.port || undefined,
    path: target.pathname + target.search, method: req.method, headers, lookup: safeLookup, timeout: TIMEOUT_MS,
    agent: target.protocol === 'https:' ? httpsAgent : httpAgent
  }, async upRes => {
    try{
      const status = upRes.statusCode;
      const sc = upRes.headers['set-cookie'];
      if(sc) (Array.isArray(sc) ? sc : [sc]).forEach(line => { const c = parseSetCookie(line, target); if(c) storeCookie(jar, c); });
      if([301, 302, 303, 307, 308].includes(status) && upRes.headers.location){
        let dest = null; try{ dest = new URL(upRes.headers.location, target).href; }catch(e){}
        upRes.resume();
        if(!dest) return send(res, 502, 'Bad redirect.');
        res.writeHead(status === 307 || status === 308 ? status : 302, { location: P + enc(dest), 'cache-control': 'no-store' });
        return res.end();
      }
      const ct = upRes.headers['content-type'] || '';
      const out = {};
      ['content-type', 'cache-control', 'etag', 'last-modified', 'content-language', 'content-disposition'].forEach(h => { if(upRes.headers[h]) out[h] = upRes.headers[h]; });
      const cenc = (upRes.headers['content-encoding'] || '').toLowerCase().trim();

      if(/text\/html|application\/xhtml/i.test(ct)){
        const buf = await inflateBody(await collect(upRes, MAX_REWRITE), cenc);
        const html = rewriteHtml(decode(buf, ct), target.href, cookiesFor(jar, target, true));
        out['content-type'] = 'text/html; charset=utf-8'; delete out.etag; delete out['last-modified']; out['cache-control'] = 'no-store';
        return await sendBody(res, status, out, html, gz);
      }
      if(/text\/css/i.test(ct)){
        const buf = await inflateBody(await collect(upRes, MAX_REWRITE), cenc);
        const css = rewriteCss(decode(buf, ct), target.href);
        out['content-type'] = 'text/css; charset=utf-8'; delete out.etag; delete out['last-modified'];
        return await sendBody(res, status, out, css, gz);
      }
      // everything else: pass the bytes straight through (already compressed by the origin if it was)
      ['content-length', 'content-range', 'accept-ranges'].forEach(h => { if(upRes.headers[h]) out[h] = upRes.headers[h]; });
      if(cenc && cenc !== 'identity') out['content-encoding'] = cenc;
      out['vary'] = 'Accept-Encoding';
      const ttl = (cacheable && status === 200) ? cacheTtl(upRes.headers) : 0;
      res.writeHead(status, out);
      let n = 0, tee = ttl > 0 ? [] : null, teeSize = 0;
      upRes.on('data', c => {
        n += c.length; if(n > MAX_STREAM){ upRes.destroy(); res.destroy(); return; }
        if(tee){ teeSize += c.length; if(teeSize > CACHE_ITEM_MAX) tee = null; else tee.push(c); }
      });
      upRes.on('end', () => {
        if(tee && upRes.complete){
          const h = Object.assign({}, out); delete h['content-length']; delete h['content-range']; delete h['accept-ranges'];
          cachePut(ckey, { headers: h, body: Buffer.concat(tee), exp: Date.now() + ttl });
        }
      });
      upRes.pipe(res);
    }catch(e){ send(res, 502, 'Could not read that page.'); }
  });
  up.on('timeout', () => up.destroy(new Error('timeout')));
  up.on('error', e => send(res, 502, 'Could not reach that site (' + (e.message === 'Blocked address' ? 'blocked address' : e.code || e.message) + ').'));
  res.on('close', () => up.destroy());
  if(body) up.write(body);
  up.end();
}

// Pages call this when their JavaScript sets document.cookie, so the cookie lands in the visitor's jar.
async function setCookieEndpoint(req, res, url){
  const target = parseTarget(url.searchParams.get('u') || '');
  if(!target || req.method !== 'POST') return send(res, 400, 'Bad request.');
  let text = ''; try{ text = (await collect(req, 8192)).toString('utf8'); }catch(e){ return send(res, 413, 'Too large.'); }
  const { sid, jar, fresh } = ensureJar(req);
  if(fresh) res.setHeader('set-cookie', sidCookie(req, sid));
  const c = parseSetCookie(text, target); if(c) storeCookie(jar, c);
  res.writeHead(204); res.end();
}

/* ---------- static files + relative-link fallback ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };
const staticCache = new Map();
function getStatic(f){
  const st = fs.statSync(f), c = staticCache.get(f);
  if(c && c.mtime === st.mtimeMs) return c;
  const raw = fs.readFileSync(f);
  const e = { mtime: st.mtimeMs, raw, gz: zlib.gzipSync(raw, { level: 9 }), etag: '"' + crypto.createHash('sha1').update(raw).digest('hex').slice(0, 16) + '"' };
  staticCache.set(f, e); return e;
}
function serveStatic(req, p, res){
  if(p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUBLIC_DIR, p));
  if(!f.startsWith(PUBLIC_DIR + path.sep)) return false;
  let e; try{ if(!fs.statSync(f).isFile()) return false; e = getStatic(f); }catch(err){ return false; }
  const h = { 'content-type': MIME[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff', 'etag': e.etag, 'vary': 'Accept-Encoding' };
  if(req.headers['if-none-match'] === e.etag){ res.writeHead(304, h); res.end(); return true; }
  const useGz = clientGzip(req) && /\.(html|js|css|svg|json)$/.test(f);
  if(useGz) h['content-encoding'] = 'gzip';
  const body = useGz ? e.gz : e.raw; h['content-length'] = body.length;
  res.writeHead(200, h); res.end(body); return true;
}
// Pages sometimes request "/foo.js" straight from our host. The Referer tells us which site it belonged to.
function fallback(req, res){
  try{
    const r = new URL(req.headers.referer || '');
    if(r.pathname === '/go'){
      const dest = new URL(req.url, r.searchParams.get('u'));
      if(dest.protocol === 'http:' || dest.protocol === 'https:'){
        res.writeHead(307, { location: P + enc(dest.href), 'cache-control': 'no-store' });
        return res.end();
      }
    }
  }catch(e){}
  send(res, 404, 'Not found');
}

const server = http.createServer((req, res) => {
  try{
    const url = new URL(req.url, 'http://localhost');
    if(url.pathname === '/healthz'){ res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); return res.end('{"mostyles":true}'); }
    if(!authOk(req, res) || !rateOk(req, res)) return;
    if(url.pathname === '/go') return proxy(req, res, url).catch(() => send(res, 500, 'Proxy error.'));
    if(url.pathname === '/__c') return setCookieEndpoint(req, res, url).catch(() => send(res, 500, 'Error.'));
    if(url.pathname === '/__burn' && req.method === 'POST'){ const sid = getSid(req); if(sid) jars.delete(sid); res.writeHead(204); return res.end(); }
    if(req.method === 'GET' && serveStatic(req, url.pathname, res)) return;
    fallback(req, res);
  }catch(e){ send(res, 500, 'Server error.'); }
});
server.requestTimeout = 60000;
server.listen(PORT, () => console.log('MoStyles running on port ' + PORT + (PASSWORD ? ' (password protected)' : ' (NO password set)')));
