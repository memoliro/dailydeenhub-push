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
  const sigDer = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(unsignedToken)));
  // DER -> raw R||S (64 bytes)
  let off = 2;
  if (sigDer[off] === 0) off++; // skip leading zero pad if present (then adjust)
  // parse properly:
  let p = 2;
  const rLen = sigDer[p + 1]; p += 2;
  let r = sigDer.slice(p, p + rLen); p += rLen;
  const sLen = sigDer[p + 1]; p += 2;
  let s = sigDer.slice(p, p + sLen);
  const raw = new Uint8Array(64);
  raw.set(r.slice(-32), 32 - Math.min(32, r.length));
  raw.set(s.slice(-32), 64 - Math.min(32, s.length));
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
  // key_info = "WebPush: info" || 0x00 || client_pub || eph_pub
  const keyInfo = concat(info('WebPush: info'), new Uint8Array([0]), clientPub, ephPubRaw);
  const ikm = await hkdfExtract(authSecret, concat(sharedSecret, keyInfo));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  // cek_info = "Content-Encoding: aes128gcm" || 0x00
  const cekInfo = concat(info('Content-Encoding: aes128gcm'), new Uint8Array([0]));
  const prk = await hkdfExtract(salt, ikm);
  const cek = await hkdfExpand(prk, cekInfo, 16);
  // nonce_info = "Content-Encoding: nonce" || 0x00
  const nonceInfo = concat(info('Content-Encoding: nonce'), new Uint8Array([0]));
  const nonce = await hkdfExpand(prk, nonceInfo, 12);

  // pad: 2-byte big-endian pad length (0) + payload
  const plaintext = concat(new Uint8Array([0, 0]), payloadBytes);
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
