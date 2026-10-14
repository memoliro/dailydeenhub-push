/* dailydeenhub-push — Web Push backend for prayer alerts.
   Routes:
     GET  /api/vapid-key          -> {key} public VAPID key (base64url)
     POST /api/subscribe          -> store push subscription + prayer settings
     POST /api/unsubscribe        -> remove by endpoint
   Cron (every minute): send due reminders, advance each sub's next_fire.
*/
import { sendPush } from './webpush.js';
import { fetchTimings, buildSchedule, todayInTz } from './prayer.js';

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
  const mins = remind[sub.next_prayer] !== undefined ? remind[sub.next_prayer] : remind['x:' + sub.next_prayer];
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
  const extraNames = lang === 'tr'
    ? { sahur: 'Sahur', tahajjud: 'Teheccüd', fast: 'Pazartesi/Perşembe orucu', fastEve: 'Yarın oruç', jumuah: 'Cuma' }
    : { sahur: 'Sahur', tahajjud: 'Tahajjud', fast: 'Mon/Thu fast', fastEve: 'Fast tomorrow', jumuah: "Jumu'ah" };
  if (extraNames[prayer]) {
    const n = extraNames[prayer];
    if (prayer === 'fastEve') return lang === 'tr' ? 'Yarın oruç — hazırlığı unutma' : "Fast tomorrow — don't forget to prepare";
    return lang === 'tr' ? `${n} — ${mins} dk kaldı` : `${n} — ${mins} min left`;
  }
  const names = lang === 'tr'
    ? { Fajr: 'İmsak', Dhuhr: 'Öğle', Asr: 'İkindi', Maghrib: 'Akşam', Isha: 'Yatsı' }
    : { Fajr: 'Fajr', Dhuhr: 'Dhuhr', Asr: 'Asr', Maghrib: 'Maghrib', Isha: 'Isha' };
  let n = names[prayer] || prayer;
  // Fridays: Dhuhr is Jumu'ah / Cuma — matches the site's nameOf() in app.js
  if (prayer === 'Dhuhr' && isFriday) n = lang === 'tr' ? 'Cuma' : "Jumu'ah";
  if (mins === 0) return lang === 'tr' ? `${n} vakti` : `${n} time`;
  return lang === 'tr' ? `${n} — ${mins} dk kaldı` : `${n} — ${mins} min left`;
}
