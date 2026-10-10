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
