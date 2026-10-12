/* Bundled single-file worker for dashboard deploy.
   Sources: src/webpush.js + src/prayer.js + src/index.js
   Built: 2026-10-11 */
/* Minimal Web Push (RFC 8291 aes128gcm + VAPID RFC 8292) for Cloudflare Workers.
   Uses WebCrypto only. No Node dependencies. */

const enc = new TextEncoder();

function b64urlEncode(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}

function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

/* HKDF-Extract + Expand (SHA-256), RFC 8291 style */
async function hkdfExtract(salt, ikm) {
  const key = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, ikm);
  return new Uint8Array(sig);
}

async function hkdfExpand(prk, info, len) {
  const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const out = new Uint8Array(len);
  let prev = new Uint8Array(0);
  let off = 0, ctr = 1;
  while (off < len) {
    const data = concat(prev, info, new Uint8Array([ctr]));
    const sig = await crypto.subtle.sign('HMAC', key, data);
    prev = new Uint8Array(sig);
    const n = Math.min(prev.length, len - off);
    out.set(prev.slice(0, n), off);
    off += n; ctr++;
  }
  return out;
}

/* VAPID JWT (ES256) */
async function vapidAuthHeader(audience, subject, privateJwk, publicB64) {
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64urlEncode(enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject,
  })));
  const unsignedToken = header + '.' + claims;
  const key = await crypto.subtle.importKey('jwk', privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sigBytes = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(unsignedToken)));
  // Normalize to raw R||S (64 bytes). Cloudflare Workers returns raw already;
  // other runtimes return DER — handle both.
  let raw;
  if (sigBytes.length === 64 && sigBytes[0] !== 0x30) {
    raw = sigBytes;
  } else {
    let p = 2;
    const rLen = sigBytes[p + 1]; p += 2;
    let r = sigBytes.slice(p, p + rLen); p += rLen;
    const sLen = sigBytes[p + 1]; p += 2;
    let s = sigBytes.slice(p, p + sLen);
    raw = new Uint8Array(64);
    raw.set(r.slice(-32), 32 - Math.min(32, r.length));
    raw.set(s.slice(-32), 64 - Math.min(32, s.length));
  }
  const jwt = unsignedToken + '.' + b64urlEncode(raw);
  return 'vapid t=' + jwt + ', k=' + publicB64;
}

/* Encrypt payload with aes128gcm (RFC 8291) */
async function encryptPayload(p256dhB64, authB64, payloadBytes) {
  const clientPub = b64urlDecode(p256dhB64);   // 65 bytes uncompressed
  const authSecret = b64urlDecode(authB64);    // 16 bytes

  // ephemeral keypair
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey)); // 65 bytes

  // shared secret
  const clientKey = await crypto.subtle.importKey('raw', clientPub,
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: clientKey }, eph.privateKey, 256);
  const sharedSecret = new Uint8Array(sharedBits);

  const info = (s) => enc.encode(s);
  // RFC 8291: secret = HKDF(auth_secret, ecdh_secret, key_info, 32)
  // key_info = "WebPush: info" || 0x00 || client_pub || eph_pub
  const keyInfo = concat(info('WebPush: info'), new Uint8Array([0]), clientPub, ephPubRaw);
  const prk1 = await hkdfExtract(authSecret, sharedSecret);
  const ikm = await hkdfExpand(prk1, keyInfo, 32);

  // RFC 8291 aes128gcm: PRK = HKDF-Extract(salt, IKM); then Expand for CEK/nonce
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk2 = await hkdfExtract(salt, ikm);
  // cek_info = "Content-Encoding: aes128gcm" || 0x00
  const cekInfo = concat(info('Content-Encoding: aes128gcm'), new Uint8Array([0]));
  const cek = await hkdfExpand(prk2, cekInfo, 16);
  // nonce_info = "Content-Encoding: nonce" || 0x00
  const nonceInfo = concat(info('Content-Encoding: nonce'), new Uint8Array([0]));
  const nonce = await hkdfExpand(prk2, nonceInfo, 12);

  // plaintext = payload || 0x02 (aes128gcm delimiter at END)
  const plaintext = concat(payloadBytes, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey, plaintext));

  // body = salt || rs(4B BE = 4096) || idlen(1B = 65) || keyid(65B eph pub) || ciphertext
  const rs = new Uint8Array([0x00, 0x00, 0x10, 0x00]);
  const idlen = new Uint8Array([65]);
  return { body: concat(salt, rs, idlen, ephPubRaw, ct), salt };
}

/* Send one push. sub = {endpoint, p256dh, auth}. payloadObj -> JSON. */
export async function sendPush(sub, payloadObj, vapid) {
  const endpoint = new URL(sub.endpoint);
  const audience = endpoint.origin;
  const payloadBytes = enc.encode(JSON.stringify(payloadObj));

  const authHeader = await vapidAuthHeader(audience, vapid.subject, vapid.privateJwk, vapid.publicB64);
  const { body } = await encryptPayload(sub.p256dh, sub.auth, payloadBytes);

  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '300',
      'Urgency': 'high',
    },
    body,
  });
  return res.status;
}
/* Prayer-time fetching (Aladhan API — same source the site uses) and
   reminder-schedule building. All times handled in UTC ISO strings. */

const PRAYERS = ['Fajr', 'Dhuhr', 'Asr', 'Maghrib', 'Isha'];

/* Fetch timings for a date (YYYY-MM-DD) at lat/lon. Returns {Prayer: "HH:MM"} in 24h. */
export async function fetchTimings(dateStr, lat, lon, method, madhab) {
  const [y, m, d] = dateStr.split('-');
  const url = `https://api.aladhan.com/v1/timings/${d}-${m}-${y}` +
    `?latitude=${lat}&longitude=${lon}&method=${method}&madhab=${madhab}`;
  const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
  if (!res.ok) throw new Error('Aladhan HTTP ' + res.status);
  const j = await res.json();
  if (j.code !== 200 || !j.data || !j.data.timings) throw new Error('Aladhan bad payload');
  const t = j.data.timings;
  const out = {};
  for (const p of PRAYERS) {
    // timings look like "05:42" or "05:42 (EET)"; take HH:MM
    const mobj = /^(\d{1,2}):(\d{2})/.exec(t[p] || '');
    if (!mobj) throw new Error('Missing timing for ' + p);
    out[p] = mobj[1].padStart(2, '0') + ':' + mobj[2];
  }
  return out;
}

/* Date string YYYY-MM-DD for "today" in a given IANA timezone. */
export function todayInTz(tz, whenMs) {
  const dtf = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
  });
  return dtf.format(new Date(whenMs)); // YYYY-MM-DD
}

/* Build reminder schedule: [{prayer, at: ISO_UTC}] sorted by time.
   remind = {Fajr: 15, ...} minutes before. tz = user's IANA timezone.
   We interpret the HH:MM as wall-clock in tz, then convert to UTC. */
export function buildSchedule(dateStr, timings, remind, tz) {
  const items = [];
  for (const p of PRAYERS) {
    const mins = remind[p];
    if (mins === undefined || mins === null) continue;
    // wall-clock -> UTC: construct via a fixed-offset trick using Intl
    const utcMs = wallToUtc(dateStr, timings[p], tz);
    const fireMs = utcMs - mins * 60 * 1000;
    items.push({ prayer: p, at: new Date(fireMs).toISOString() });
  }
  items.sort((a, b) => a.at < b.at ? -1 : 1);
  return items;
}

/* Convert YYYY-MM-DD + HH:MM wall-clock in tz to UTC milliseconds. */
function wallToUtc(dateStr, hm, tz) {
  const [Y, M, D] = dateStr.split('-').map(Number);
  const [h, mi] = hm.split(':').map(Number);
  // guess: treat as UTC, then correct by the tz offset at that moment
  const guessUtc = Date.UTC(Y, M - 1, D, h, mi);
  const off = tzOffsetMs(tz, guessUtc);
  return guessUtc - off;
}

function tzOffsetMs(tz, utcMs) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
  const parts = Object.fromEntries(dtf.formatToParts(new Date(utcMs)).map(p => [p.type, p.value]));
  const asUtc = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour % 24, +parts.minute, +parts.second);
  return asUtc - utcMs;
}
/* dailydeenhub-push — Web Push backend for prayer alerts.
   Routes:
     GET  /api/vapid-key          -> {key} public VAPID key (base64url)
     POST /api/subscribe          -> store push subscription + prayer settings
     POST /api/unsubscribe        -> remove by endpoint
   Cron (every minute): send due reminders, advance each sub's next_fire.
*/

const ALLOWED_ORIGINS = new Set([
  'https://dailydeenhub.com',
  'https://www.dailydeenhub.com',
]);

function corsHeaders(req) {
  const origin = req.headers.get('Origin') || '';
  const h = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (ALLOWED_ORIGINS.has(origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Vary'] = 'Origin';
  }
  return h;
}

function json(req, obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(req) },
  });
}

function vapidEnv(env) {
  return {
    subject: env.VAPID_SUBJECT || 'mailto:memoliro@gmail.com',
    publicB64: env.VAPID_PUBLIC,
    privateJwk: JSON.parse(env.VAPID_PRIVATE_JWK),
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(req) });

    if (url.pathname === '/api/vapid-key' && req.method === 'GET') {
      return json(req, { key: env.VAPID_PUBLIC });
    }

    if (url.pathname === '/api/subscribe' && req.method === 'POST') {
      let b;
      try { b = await req.json(); } catch { return json(req, { error: 'bad json' }, 400); }
      const sub = b.subscription || {};
      if (!sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
        return json(req, { error: 'bad subscription' }, 400);
      }
      const s = b.settings || {};
      if (typeof s.lat !== 'number' || typeof s.lon !== 'number' || !s.tz) {
        return json(req, { error: 'bad settings' }, 400);
      }
      const remind = s.remind || {};
      // compute first schedule so next_fire is set immediately
      const nowMs = Date.now();
      const dateStr = todayInTz(s.tz, nowMs);
      let sched;
      try {
        const timings = await fetchTimings(dateStr, s.lat, s.lon, s.method ?? 2, s.madhab ?? 0);
        sched = buildSchedule(dateStr, timings, remind, s.tz);
      } catch (e) {
        return json(req, { error: 'timings unavailable: ' + e.message }, 502);
      }
      const upcoming = sched.find(i => i.at > new Date(nowMs).toISOString());
      await env.DB.prepare(
        `INSERT INTO subs (endpoint, p256dh, auth, lat, lon, tz, method, madhab, remind_json, lang, schedule_date, next_fire, next_prayer, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(endpoint) DO UPDATE SET
           p256dh=excluded.p256dh, auth=excluded.auth, lat=excluded.lat, lon=excluded.lon,
           tz=excluded.tz, method=excluded.method, madhab=excluded.madhab,
           remind_json=excluded.remind_json, lang=excluded.lang,
           schedule_date=excluded.schedule_date, next_fire=excluded.next_fire,
           next_prayer=excluded.next_prayer, updated_at=datetime('now')`
      ).bind(
        sub.endpoint, sub.keys.p256dh, sub.keys.auth,
        s.lat, s.lon, s.tz, s.method ?? 2, s.madhab ?? 0,
        JSON.stringify(remind), s.lang || 'en', dateStr,
        upcoming ? upcoming.at : null, upcoming ? upcoming.prayer : null
      ).run();
      return json(req, { ok: true, next_fire: upcoming ? upcoming.at : null });
    }

    if (url.pathname === '/api/debug' && req.method === 'GET') {
      const rows = await env.DB.prepare(
        `SELECT substr(endpoint,1,50) AS ep, next_fire, next_prayer, schedule_date, tz, lang, updated_at FROM subs ORDER BY updated_at DESC LIMIT 20`
      ).run();
      return json(req, {
        now: new Date().toISOString(),
        count: (rows.results || []).length,
        subs: rows.results || [],
      });
    }

    if (url.pathname === '/api/unsubscribe' && req.method === 'POST') {
      let b;
      try { b = await req.json(); } catch { return json(req, { error: 'bad json' }, 400); }
      if (!b.endpoint) return json(req, { error: 'missing endpoint' }, 400);
      await env.DB.prepare('DELETE FROM subs WHERE endpoint = ?').bind(b.endpoint).run();
      return json(req, { ok: true });
    }

    return json(req, { error: 'not found' }, 404);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runDueReminders(env));
  },
};

async function runDueReminders(env) {
  const nowIso = new Date().toISOString();
  const vapid = vapidEnv(env);
  // subs whose next reminder is due (allow 90s grace for cron jitter)
  const due = await env.DB.prepare(
    `SELECT * FROM subs WHERE next_fire IS NOT NULL AND next_fire <= ?`
  ).bind(new Date(Date.now() + 90 * 1000).toISOString()).run();

  for (const sub of due.results || []) {
    try {
      await handleOneSub(env, sub, vapid);
    } catch (e) {
      console.log('sub failed', sub.endpoint.slice(0, 40), e.message);
    }
  }
}

async function handleOneSub(env, sub, vapid) {
  const nowMs = Date.now();
  const remind = JSON.parse(sub.remind_json || '{}');

  // 1. send the push for the due prayer
  const mins = remind[sub.next_prayer];
  // schedule_date is the prayer's local date (YYYY-MM-DD in sub.tz);
  // noon UTC keeps the weekday lookup immune to timezone shifts.
  const isFriday = sub.schedule_date
    ? new Date(sub.schedule_date + 'T12:00:00Z').getUTCDay() === 5
    : false;
  const title = prayerTitle(sub.next_prayer, sub.lang, mins, isFriday);
  const status = await sendPush(
    { endpoint: sub.endpoint, p256dh: sub.p256dh, auth: sub.auth },
    { title, prayer: sub.next_prayer, mins, url: 'https://dailydeenhub.com/' },
    vapid
  );
  if (status === 404 || status === 410) {
    // subscription dead — remove it
    await env.DB.prepare('DELETE FROM subs WHERE endpoint = ?').bind(sub.endpoint).run();
    return;
  }

  // 2. advance to the next reminder
  let dateStr = todayInTz(sub.tz, nowMs);
  let sched;
  if (sub.schedule_date === dateStr) {
    // rebuild from the same timings is wasteful; recompute cheaply via API (cached by Aladhan CDN)
    const timings = await fetchTimings(dateStr, sub.lat, sub.lon, sub.method, sub.madhab);
    sched = buildSchedule(dateStr, timings, remind, sub.tz);
  } else {
    const timings = await fetchTimings(dateStr, sub.lat, sub.lon, sub.method, sub.madhab);
    sched = buildSchedule(dateStr, timings, remind, sub.tz);
  }
  let upcoming = sched.find(i => i.at > new Date(nowMs).toISOString());
  if (!upcoming) {
    // nothing left today — schedule tomorrow's first
    const tomorrowMs = nowMs + 24 * 3600 * 1000;
    const tomorrowStr = todayInTz(sub.tz, tomorrowMs);
    const timings = await fetchTimings(tomorrowStr, sub.lat, sub.lon, sub.method, sub.madhab);
    const sched2 = buildSchedule(tomorrowStr, timings, remind, sub.tz);
    upcoming = sched2[0] || null;
    dateStr = tomorrowStr;
  }
  await env.DB.prepare(
    `UPDATE subs SET schedule_date = ?, next_fire = ?, next_prayer = ?, updated_at = datetime('now') WHERE endpoint = ?`
  ).bind(dateStr, upcoming ? upcoming.at : null, upcoming ? upcoming.prayer : null, sub.endpoint).run();
}

function prayerTitle(prayer, lang, mins, isFriday) {
  const names = lang === 'tr'
    ? { Fajr: 'İmsak', Dhuhr: 'Öğle', Asr: 'İkindi', Maghrib: 'Akşam', Isha: 'Yatsı' }
    : { Fajr: 'Fajr', Dhuhr: 'Dhuhr', Asr: 'Asr', Maghrib: 'Maghrib', Isha: 'Isha' };
  let n = names[prayer] || prayer;
  // Fridays: Dhuhr is Jumu'ah / Cuma — matches the site's nameOf() in app.js
  if (prayer === 'Dhuhr' && isFriday) n = lang === 'tr' ? 'Cuma' : "Jumu'ah";
  if (mins === 0) return lang === 'tr' ? `${n} vakti` : `${n} time`;
  return lang === 'tr' ? `${n} — ${mins} dk kaldı` : `${n} — ${mins} min left`;
}
