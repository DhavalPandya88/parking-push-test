// webpush-lite.js
// A dependency-free implementation of Web Push (RFC 8291 encryption + RFC 8292 VAPID auth)
// using only Node's built-in `crypto` and `https`/`http` modules. No npm packages required.

const crypto = require('crypto');
const https = require('https');
const http = require('http');

function b64urlToBuf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function bufToB64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

// Single-block HKDF-Expand (sufficient since we only ever need <= 32 bytes of output)
function hkdfExpand(prk, info, length) {
  const infoBuf = Buffer.concat([info, Buffer.from([1])]);
  return hmacSha256(prk, infoBuf).slice(0, length);
}

function buildVapidPrivateKeyObject(vapidPublicKeyB64url, vapidPrivateKeyB64url) {
  const pubBuf = b64urlToBuf(vapidPublicKeyB64url); // 65 bytes: 0x04 || X(32) || Y(32)
  const x = pubBuf.slice(1, 33);
  const y = pubBuf.slice(33, 65);
  const d = b64urlToBuf(vapidPrivateKeyB64url); // 32 bytes
  const jwk = { kty: 'EC', crv: 'P-256', x: bufToB64url(x), y: bufToB64url(y), d: bufToB64url(d) };
  return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
}

function base64urlJSON(obj) {
  return bufToB64url(Buffer.from(JSON.stringify(obj)));
}

function createVapidJWT(audience, subject, privateKeyObj) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: audience, exp: now + 12 * 3600, sub: subject };
  const unsigned = base64urlJSON(header) + '.' + base64urlJSON(payload);
  const sig = crypto.sign('sha256', Buffer.from(unsigned), { key: privateKeyObj, dsaEncoding: 'ieee-p1363' });
  return unsigned + '.' + bufToB64url(sig);
}

// RFC 8291 message encryption (aes128gcm). Returns the full request body
// (header + ciphertext) ready to POST to the push service.
function encryptPayload(payloadBuffer, userPublicKeyB64url, userAuthB64url) {
  const userPublicKey = b64urlToBuf(userPublicKeyB64url); // 65 bytes
  const userAuth = b64urlToBuf(userAuthB64url); // 16 bytes

  const localCurve = crypto.createECDH('prime256v1');
  localCurve.generateKeys();
  const asPublicKey = localCurve.getPublicKey(); // 65 bytes, uncompressed point
  const sharedSecret = localCurve.computeSecret(userPublicKey); // 32 bytes

  const salt = crypto.randomBytes(16);

  const authInfo = Buffer.concat([Buffer.from('WebPush: info\0', 'utf8'), userPublicKey, asPublicKey]);
  const prkKey = hmacSha256(userAuth, sharedSecret);
  const ikm = hkdfExpand(prkKey, authInfo, 32);

  const prk = hmacSha256(salt, ikm);

  const cek = hkdfExpand(prk, Buffer.from('Content-Encoding: aes128gcm\0', 'utf8'), 16);
  const nonce = hkdfExpand(prk, Buffer.from('Content-Encoding: nonce\0', 'utf8'), 12);

  // Single record (last record): append 0x02 delimiter, no extra padding.
  const paddedPlaintext = Buffer.concat([payloadBuffer, Buffer.from([2])]);

  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(paddedPlaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedRecord = Buffer.concat([ciphertext, authTag]);

  const recordSize = Buffer.alloc(4);
  recordSize.writeUInt32BE(4096, 0);
  const idLen = Buffer.from([asPublicKey.length]);

  const header = Buffer.concat([salt, recordSize, idLen, asPublicKey]);
  return Buffer.concat([header, encryptedRecord]);
}

function sendWebPush(subscription, payloadObj, vapidPublicKey, vapidPrivateKey, subject) {
  return new Promise((resolve, reject) => {
    try {
      const payloadBuffer = Buffer.from(JSON.stringify(payloadObj), 'utf8');
      const body = encryptPayload(payloadBuffer, subscription.keys.p256dh, subscription.keys.auth);

      const urlObj = new URL(subscription.endpoint);
      const audience = urlObj.origin;
      const privateKeyObj = buildVapidPrivateKeyObject(vapidPublicKey, vapidPrivateKey);
      const jwt = createVapidJWT(audience, subject, privateKeyObj);

      const headers = {
        'Content-Type': 'application/octet-stream',
        'Content-Encoding': 'aes128gcm',
        'Content-Length': body.length,
        'TTL': '86400',
        'Authorization': `vapid t=${jwt}, k=${vapidPublicKey}`
      };

      const transport = urlObj.protocol === 'http:' ? http : https;
      const req = transport.request(
        { hostname: urlObj.hostname, port: urlObj.port || undefined, path: urlObj.pathname + urlObj.search, method: 'POST', headers },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve({ statusCode: res.statusCode, body: data });
            } else {
              reject(new Error(`Push service responded ${res.statusCode}: ${data}`));
            }
          });
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { sendWebPush, encryptPayload, b64urlToBuf, bufToB64url };
