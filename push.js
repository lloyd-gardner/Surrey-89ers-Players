/* ============================================================
   Surrey 89ers — push notification sender
   ------------------------------------------------------------
   The Apps Script endpoint decides WHO gets a notification and
   WHEN. This function only does the part Apps Script cannot:
   the encryption and signing that Apple and Google require
   before they will deliver a notification to a phone.

   GET  /api/push   -> { ok, publicKey }   (the portal reads this
                       to subscribe a phone; the key is public)
   POST /api/push   -> sends notifications. Needs the shared
                       secret, so only the Apps Script can call it.
        body: { messages: [ { subscription:{endpoint,keys:{p256dh,auth}},
                              payload:{title,body,url,tag}, ttl } ] }
        reply: { ok, results:[ {status, ok, gone} ] }  (same order)

   Three settings, kept in Vercel (Project > Settings >
   Environment Variables) and never in this public repo:
     VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, PUSH_SECRET

   No dependencies: Web Push (RFC 8291 + 8292) on Node's own crypto.
   ============================================================ */
const crypto = require("node:crypto");

const SUBJECT = process.env.VAPID_SUBJECT || "https://surrey-89ers-players.vercel.app";
const MAX_MESSAGES = 200;

/* Only ever talk to the real push services, never an arbitrary URL. */
const PUSH_HOSTS = [
  /^fcm\.googleapis\.com$/,                    // Chrome, Android, Edge
  /^[a-z0-9-]+\.push\.apple\.com$/,            // Safari, iPhone, iPad
  /^updates\.push\.services\.mozilla\.com$/,   // Firefox
  /^[a-z0-9-]+\.notify\.windows\.com$/         // Edge on Windows
];

const b64u  = (buf) => Buffer.from(buf).toString("base64url");
const unb64 = (str) => Buffer.from(String(str || "").replace(/=+$/, ""), "base64url");

function config(){
  const pub  = (process.env.VAPID_PUBLIC_KEY  || "").trim();
  const priv = (process.env.VAPID_PRIVATE_KEY || "").trim();
  const secret = (process.env.PUSH_SECRET || "").trim();
  const pubBytes = unb64(pub), privBytes = unb64(priv);
  const ok = pubBytes.length === 65 && pubBytes[0] === 4 && privBytes.length === 32 && secret.length >= 16;
  return { ok, pub, pubBytes, privBytes, secret };
}

function allowedEndpoint(endpoint){
  let u;
  try{ u = new URL(endpoint); }catch(e){ return null; }
  if(u.protocol !== "https:") return null;
  return PUSH_HOSTS.some((re) => re.test(u.hostname)) ? u : null;
}

/* VAPID (RFC 8292): a short-lived signed token that tells the push
   service which server is sending. */
function vapidHeader(cfg, audience, now){
  const key = crypto.createPrivateKey({ format: "jwk", key: {
    kty: "EC", crv: "P-256",
    x: b64u(cfg.pubBytes.subarray(1, 33)),
    y: b64u(cfg.pubBytes.subarray(33, 65)),
    d: b64u(cfg.privBytes)
  }});
  const head   = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64u(JSON.stringify({ aud: audience, exp: Math.floor(now / 1000) + 12 * 3600, sub: SUBJECT }));
  const sig = crypto.sign("sha256", Buffer.from(head + "." + claims), { key, dsaEncoding: "ieee-p1363" });
  return "vapid t=" + head + "." + claims + "." + b64u(sig) + ", k=" + b64u(cfg.pubBytes);
}

/* Message encryption (RFC 8291, aes128gcm). `opts` exists only so the
   tests can pin the random parts; real sends never pass it. */
function encrypt(subscription, plaintext, opts){
  opts = opts || {};
  const uaPublic = unb64(subscription.keys.p256dh);
  const authSecret = unb64(subscription.keys.auth);
  if(uaPublic.length !== 65 || authSecret.length !== 16) throw new Error("bad subscription keys");

  const ecdh = crypto.createECDH("prime256v1");
  if(opts.privateKey) ecdh.setPrivateKey(opts.privateKey); else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const shared = ecdh.computeSecret(uaPublic);
  const salt = opts.salt || crypto.randomBytes(16);

  const keyInfo = Buffer.concat([Buffer.from("WebPush: info\0"), uaPublic, asPublic]);
  const ikm   = Buffer.from(crypto.hkdfSync("sha256", shared, authSecret, keyInfo, 32));
  const cek   = Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16));
  const nonce = Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));

  const cipher = crypto.createCipheriv("aes-128-gcm", cek, nonce);
  const body = Buffer.concat([
    cipher.update(Buffer.concat([Buffer.from(plaintext), Buffer.from([2])])),  // 0x02 = last record
    cipher.final(), cipher.getAuthTag()
  ]);

  const header = Buffer.alloc(21);
  salt.copy(header, 0);
  header.writeUInt32BE(4096, 16);   // record size
  header.writeUInt8(65, 20);        // length of the key that follows
  return Buffer.concat([header, asPublic, body]);
}

async function sendOne(cfg, msg){
  try{
    const sub = msg && msg.subscription;
    const url = sub && allowedEndpoint(sub.endpoint);
    if(!url || !sub.keys) return { status: 0, ok: false, gone: false, error: "invalid subscription" };

    const text = JSON.stringify(msg.payload || {});
    if(Buffer.byteLength(text) > 3000) return { status: 0, ok: false, gone: false, error: "payload too large" };

    const ttl = Math.max(0, Math.min(Number(msg.ttl) || 6 * 3600, 28 * 86400));
    const res = await fetch(sub.endpoint, {
      method: "POST",
      headers: {
        "Authorization": vapidHeader(cfg, url.origin, Date.now()),
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "TTL": String(ttl),
        "Urgency": "normal"
      },
      body: encrypt(sub, text),
      signal: AbortSignal.timeout(8000)
    });
    const out = { status: res.status, ok: res.status >= 200 && res.status < 300,
                  /* 404/410: the phone has unsubscribed — the caller should forget it */
                  gone: res.status === 404 || res.status === 410 };
    if(!out.ok) out.error = (await res.text().catch(() => "")).slice(0, 200);
    return out;
  }catch(err){
    return { status: 0, ok: false, gone: false, error: String(err && err.message || err).slice(0, 200) };
  }
}

function authorised(req, secret){
  const given = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(secret).digest();
  return crypto.timingSafeEqual(a, b);
}

async function handler(req, res){
  const cfg = config();
  res.setHeader("Cache-Control", "no-store");

  if(req.method === "GET"){
    return res.status(200).json(cfg.ok ? { ok: true, publicKey: cfg.pub }
                                       : { ok: false, error: "push is not configured yet" });
  }
  if(req.method !== "POST") return res.status(405).json({ ok: false, error: "method not allowed" });
  if(!cfg.ok) return res.status(503).json({ ok: false, error: "push is not configured yet" });
  if(!authorised(req, cfg.secret)) return res.status(401).json({ ok: false, error: "unauthorised" });

  let body = req.body;
  if(typeof body === "string"){ try{ body = JSON.parse(body); }catch(e){ body = null; } }
  const messages = body && body.messages;
  if(!Array.isArray(messages)) return res.status(400).json({ ok: false, error: "messages must be a list" });
  if(messages.length > MAX_MESSAGES) return res.status(400).json({ ok: false, error: "too many messages" });

  const results = await Promise.all(messages.map((m) => sendOne(cfg, m)));
  return res.status(200).json({ ok: true, results });
}

module.exports = handler;
module.exports._test = { encrypt, vapidHeader, config, allowedEndpoint, sendOne };
