 require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Stripe = require("stripe");
const app = express();
const Resend = require("resend").Resend;
const resend = new Resend(process.env.RESEND_API_KEY);
const paymentsRouter = require("./routes/payments");
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;
const SITE_URL = (
  process.env.TMKP_SITE_URL || "https://themasterkeyprogram.com"
).replace(/\/+$/, "");
// -------------------------
// Configuración de servidor
// -------------------------
const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
console.error("[WARN] Falta DATABASE_URL en .env");
}
if (!process.env.JWT_SECRET) {
console.error("[WARN] Falta JWT_SECRET en .env");
}
// -------------------------
// Pool de PostgreSQL (Neon)
// -------------------------
const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: {
rejectUnauthorized: false,
},
});
const EMAIL_CHANGE_TTL_MINUTES = 15;
const EMAIL_CHANGE_RESEND_SECONDS = 60;
const EMAIL_CHANGE_MAX_ATTEMPTS = 5;
function normalizeEmail(emailRaw) {
return String(emailRaw || "").trim().toLowerCase();
}
function isValidEmail(email) {
return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ""));
}
function hashEmailChangeCode(code) {
return crypto
.createHmac("sha256", process.env.JWT_SECRET || "tmkp-email-change")
.update(String(code))
.digest("hex");
}
function hashContinuationToken(token) {
  return crypto
    .createHash("sha256")
    .update(String(token || ""))
    .digest("hex");
} 
async function ensureAccountSecurityTables() {
try {
// Permanent aliases/history for account emails. This lets TMKP remember
// that an old email belongs to an existing member even after the member
// changes the login email.
await pool.query(`
CREATE TABLE IF NOT EXISTS account_email_history (
id BIGSERIAL PRIMARY KEY,
user_id BIGINT NOT NULL,
email TEXT NOT NULL,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
await pool.query(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_email_history_email
ON account_email_history (LOWER(email));
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_account_email_history_user_id
ON account_email_history (user_id);
`);
// One active email-change request per user.
await pool.query(`
CREATE TABLE IF NOT EXISTS email_change_requests (
user_id BIGINT PRIMARY KEY,
new_email TEXT NOT NULL,
code_hash TEXT NOT NULL,
attempts INTEGER NOT NULL DEFAULT 0,
expires_at TIMESTAMPTZ NOT NULL,
last_sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
// Stripe table is created by routes/payments.js. IF EXISTS makes this
// safe even during a fresh startup.
await pool.query(`
ALTER TABLE IF EXISTS stripe_checkout_access
ADD COLUMN IF NOT EXISTS user_id BIGINT;
`);
await pool.query(`
ALTER TABLE users
ADD COLUMN IF NOT EXISTS stripe_connect_account_id TEXT;
`); 
 await pool.query(`
CREATE TABLE IF NOT EXISTS referral_rewards (
  id BIGSERIAL PRIMARY KEY,
  referral_checkout_id BIGINT NOT NULL UNIQUE,
  sponsor_user_id BIGINT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'usd',
  status TEXT NOT NULL DEFAULT 'pending',
  stripe_transfer_id TEXT UNIQUE,
  qualified_at TIMESTAMPTZ,
  transferred_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
 await pool.query(`
CREATE INDEX IF NOT EXISTS idx_referral_rewards_sponsor_status
ON referral_rewards (sponsor_user_id, status);
`);
// Reserve all current account emails.
await pool.query(`
INSERT INTO account_email_history (user_id, email)
SELECT id, LOWER(email)
FROM users
WHERE email IS NOT NULL AND TRIM(email) <> ''
ON CONFLICT DO NOTHING;
`);
// Best-effort backfill for already-consumed Stripe payments created
// before user_id linkage was added.
await pool.query(`
UPDATE stripe_checkout_access AS sca
SET user_id = u.id,
updated_at = NOW()
FROM users AS u
WHERE sca.user_id IS NULL
AND sca.signup_used = TRUE
AND LOWER(sca.email) = LOWER(u.email);
`).catch(() => {});
} catch (err) {
console.error("ensureAccountSecurityTables error:", err);
}
}
const accountSecurityReady = ensureAccountSecurityTables();
// =========================================================
// TMKP CONTENT PROGRESS - STEP 1
// Database structure only.
// PostgreSQL will be the official source of member progress.
// This block does NOT change any existing login, Stripe,
// email, dashboard, E-Book, or TTP behavior.
// =========================================================
const CONTENT_PROGRESS_DEFINITIONS = [
{
contentKey: "ebook_abundance",
contentType: "ebook",
titleEs: "Yo Decido Ser Abundante",
titleEn: "I Choose To Be Abundant",
totalUnits: 10,
sortOrder: 10,
},
{
contentKey: "truth_path",
contentType: "program",
titleEs: "The Truth Path",
titleEn: "The Truth Path",
totalUnits: 40,
sortOrder: 20,
},
];
async function ensureContentProgressTables() {
try {
// Small catalog of TMKP books/programs.
await pool.query(`
CREATE TABLE IF NOT EXISTS content_catalog (
content_key TEXT PRIMARY KEY,
content_type TEXT NOT NULL,
title_es TEXT NOT NULL,
title_en TEXT NOT NULL,
total_units INTEGER NOT NULL CHECK (total_units > 0),
sort_order INTEGER NOT NULL DEFAULT 0,
is_active BOOLEAN NOT NULL DEFAULT TRUE,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
// Only members who actually begin/unlock content receive rows here.
// We do NOT create empty progress rows for every registered member.
await pool.query(`
CREATE TABLE IF NOT EXISTS user_content_progress (
user_id BIGINT NOT NULL,
content_key TEXT NOT NULL
REFERENCES content_catalog(content_key)
ON DELETE CASCADE,
current_unit INTEGER NOT NULL DEFAULT 0
CHECK (current_unit >= 0),
status TEXT NOT NULL DEFAULT 'locked'
CHECK (
status IN (
'locked',
'unlocked',
'in_progress',
'completed'
)
),
unlocked_at TIMESTAMPTZ,
started_at TIMESTAMPTZ,
completed_at TIMESTAMPTZ,
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
PRIMARY KEY (user_id, content_key)
);
`);
// Useful later for Supervisor reports and completion statistics.
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_user_content_progress_content_status
ON user_content_progress (content_key, status);
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_user_content_progress_updated_at
ON user_content_progress (updated_at DESC);
`);
 await pool.query(`
  ALTER TABLE user_content_progress
  ADD COLUMN IF NOT EXISTS resume_unit INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS resume_updated_at TIMESTAMPTZ;
`);
// Seed/update only the content catalog.
// This creates TWO tiny catalog rows, not rows for every member.
for (const item of CONTENT_PROGRESS_DEFINITIONS) {
await pool.query(
`
INSERT INTO content_catalog (
content_key,
content_type,
title_es,
title_en,
total_units,
sort_order,
is_active,
updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,TRUE,NOW())
ON CONFLICT (content_key)
DO UPDATE SET
content_type = EXCLUDED.content_type,
title_es = EXCLUDED.title_es,
title_en = EXCLUDED.title_en,
total_units = EXCLUDED.total_units,
sort_order = EXCLUDED.sort_order,
is_active = TRUE,
updated_at = NOW();
`,
[
item.contentKey,
item.contentType,
item.titleEs,
item.titleEn,
item.totalUnits,
item.sortOrder,
]
);
}
 await pool.query(`
  UPDATE user_content_progress AS p
  SET status = 'in_progress',
      completed_at = NULL,
      updated_at = NOW()
  FROM content_catalog AS c
  WHERE p.content_key = c.content_key
    AND p.status = 'completed'
    AND p.current_unit < c.total_units;
`);
console.log("[OK] TMKP content progress tables ready");
} catch (err) {
console.error("ensureContentProgressTables error:", err);
}
}
const contentProgressReady = ensureContentProgressTables();
// =========================================================
// END TMKP CONTENT PROGRESS - STEP 1
// =========================================================
// -------------------------
// Middlewares globales
// -------------------------
app.use(cors());
// Stripe necesita el body original (raw) para verificar la firma del webhook.
// Conservamos el Buffer solo para /payments/webhook y dejamos express.json()
// funcionando normalmente para todas las demas rutas.
app.use(
express.json({
verify: (req, res, buf) => {
if (req.originalUrl === "/payments/webhook") {
req.rawBody = buf;
}
},
})
);
app.use("/payments", paymentsRouter);
// -------------------------
// Helpers
// -------------------------
/**
* Crea el token JWT incluyendo si es admin.
*/
function createToken(user) {
const payload = {
userId: user.id,
isAdmin: !!user.is_admin,
};
return jwt.sign(payload, process.env.JWT_SECRET, {
expiresIn: "30d",
});
}
/**
* Limpia el usuario para responder al frontend.
*/
function buildUserResponse(row) {
if (!row) return null;
return {
id: row.id,
full_name: row.full_name,
email: row.email,
phone: row.phone,
username: row.username,
refid: row.refid,
referredby: row.referredby,
referrals: row.referrals || 0,
is_admin: !!row.is_admin,
created_at: row.created_at,
lang: row.lang || "es",
country: row.country || null,
};
}
/**
* Normaliza teléfono (muy básico: solo dígitos).
*/
function normalizePhone(phoneRaw) {
if (!phoneRaw) return "";
return String(phoneRaw).replace(/\D+/g, "");
}
/**
* Genera un username simple a partir del email si no se envía.
*/
function usernameFromEmail(email) {
if (!email) return null;
const [localPart] = email.split("@");
return localPart.replace(/[^a-zA-Z0-9._-]/g, "").toLowerCase();
}
/**
* Genera refid: username limpio (máx 8) + últimos 3 dígitos del teléfono
*/
function generateRefId(username, phoneDigits) {
const base = (username || "user").replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
const short = base.slice(0, 8);
const last3 = (phoneDigits || "").slice(-3) || "000";
return `${short}${last3}`;
}
// -------------------------
// Middlewares de auth
// -------------------------
/**
* Autenticación normal de usuario (token JWT).
*/
function authMiddleware(req, res, next) {
const authHeader = req.headers.authorization || "";
const token = authHeader.startsWith("Bearer ")
? authHeader.slice(7)
: null;
if (!token) {
return res.status(401).json({ ok: false, error: "No token provided" });
}
try {
const decoded = jwt.verify(token, process.env.JWT_SECRET);
req.userId = decoded.userId;
req.jwtPayload = decoded;
next();
} catch (err) {
console.error("authMiddleware error:", err);
return res.status(401).json({ ok: false, error: "Invalid or expired token" });
}
}
/**
* Autenticación solo para administradores.
*/
function adminAuthMiddleware(req, res, next) {
const authHeader = req.headers.authorization || "";
const token = authHeader.startsWith("Bearer ")
? authHeader.slice(7)
: null;
if (!token) {
return res.status(401).json({ ok: false, error: "No admin token provided" });
}
try {
const decoded = jwt.verify(token, process.env.JWT_SECRET);
if (!decoded.isAdmin) {
return res.status(403).json({ ok: false, error: "Not an admin" });
}
req.adminId = decoded.userId;
req.adminPayload = decoded;
next();
} catch (err) {
console.error("adminAuthMiddleware error:", err);
return res.status(401).json({ ok: false, error: "Invalid or expired token" });
}
}
// -------------------------
// STRIPE CONNECT: iniciar onboarding
// -------------------------
app.post("/connect/onboarding", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({
        ok: false,
        error: "Stripe is not configured.",
      });
    }

    const { rows } = await pool.query(
      `
      SELECT
        id,
        email,
        country,
        stripe_connect_account_id
      FROM users
      WHERE id = $1
      LIMIT 1;
      `,
      [req.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Usuario no encontrado",
      });
    }

    const user = rows[0];
    const country = String(user.country || "").trim().toUpperCase();

    if (!/^[A-Z]{2}$/.test(country)) {
      return res.status(400).json({
        ok: false,
        error: "Missing or invalid country.",
      });
    }
   if (country !== "US") {
  return res.status(400).json({
    ok: false,
    code: "CONNECT_COUNTRY_NOT_YET_SUPPORTED",
    error: "Stripe Connect payouts are not yet enabled for this country.",
  });
}

let accountId = String(user.stripe_connect_account_id || "").trim();

if (!accountId) {
  const account = await stripe.accounts.create(
    {
      country,
      email: user.email,
      controller: {
        fees: { payer: "application" },
        losses: { payments: "application" },
        stripe_dashboard: { type: "express" },
      },
      capabilities: {
        transfers: { requested: true },
      },
 ...(country === "US"
  ? {}
  : {
      tos_acceptance: {
        service_agreement: "recipient",
      },
    }), 
      metadata: {
        tmkp_user_id: String(user.id),
      },
    },
    {
    idempotencyKey: `tmkp-connect-user-${user.id}-v4`, 
    }
  );

  accountId = account.id;

  await pool.query(
    `
    UPDATE users
    SET stripe_connect_account_id = $1
    WHERE id = $2;
    `,
    [accountId, user.id]
  );
}

const accountLink = await stripe.accountLinks.create({
  account: accountId,
  refresh_url: `${SITE_URL}/dashboard.html?connect=refresh`,
  return_url: `${SITE_URL}/dashboard.html?connect=complete`,
  type: "account_onboarding",
});

return res.json({
  ok: true,
  onboardingUrl: accountLink.url,
}); 

  } catch (err) {
    console.error("POST /connect/onboarding error:", err);

    return res.status(500).json({
      ok: false,
      error: "Could not start Stripe Connect onboarding.",
    });
  }
});
// -------------------------
// STRIPE CONNECT: estado del miembro
// -------------------------
app.get("/connect/status", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({
        ok: false,
        error: "Stripe is not configured.",
      });
    }

    const { rows } = await pool.query(
      `
      SELECT stripe_connect_account_id
      FROM users
      WHERE id = $1
      LIMIT 1;
      `,
      [req.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Usuario no encontrado",
      });
    }

    const accountId = String(
      rows[0].stripe_connect_account_id || ""
    ).trim();

    if (!accountId) {
      return res.json({
        ok: true,
        started: false,
        ready: false,
      });
    }

    const account = await stripe.accounts.retrieve(accountId);

    return res.json({
      ok: true,
      started: true,
      ready:
        account.details_submitted === true &&
        account.payouts_enabled === true,
      detailsSubmitted: account.details_submitted === true,
      payoutsEnabled: account.payouts_enabled === true,
    });
  } catch (err) {
    console.error("GET /connect/status error:", err);

    return res.status(500).json({
      ok: false,
      error: "Could not retrieve Stripe Connect status.",
    });
  }
});
// -------------------------
// STRIPE CONNECT: transferencia de prueba
// -------------------------
app.post("/connect/test-transfer", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({
        ok: false,
        error: "Stripe is not configured.",
      });
    }

    const testRewardCents = Number(
      process.env.TMKP_LIVE_TEST_REWARD_CENTS || 0
    );

    if (
      !Number.isInteger(testRewardCents) ||
      testRewardCents <= 0
    ) {
      return res.status(503).json({
        ok: false,
        error: "Live test reward is not configured.",
      });
    }
if (req.body?.confirm !== "SEND_LIVE_TEST_REWARD") {
  return res.status(400).json({
    ok: false,
    code: "CONFIRMATION_REQUIRED",
    error: "Explicit confirmation is required for the live test transfer.",
  });
}
 const { rows } = await pool.query(
  `
  SELECT
    r.id,
    r.amount_cents,
    r.currency,
    r.status,
    u.stripe_connect_account_id
  FROM referral_rewards r
  JOIN users u
    ON u.id = r.sponsor_user_id
  WHERE r.sponsor_user_id = $1
    AND r.amount_cents = $2
    AND r.status = 'pending'
  ORDER BY r.qualified_at ASC NULLS LAST, r.id ASC
  LIMIT 1;
  `,
  [req.userId, testRewardCents]
);

if (rows.length === 0) {
  return res.status(404).json({
    ok: false,
    code: "NO_PENDING_TEST_REWARD",
    error: "No pending test reward found.",
  });
}
const reward = rows[0];

const accountId = String(
  reward.stripe_connect_account_id || ""
).trim();

if (!accountId) {
  return res.status(400).json({
    ok: false,
    code: "CONNECT_NOT_CONFIGURED",
    error: "Stripe Connect is not configured.",
  });
}

const account = await stripe.accounts.retrieve(accountId);

 if (
  account.details_submitted !== true ||
  account.payouts_enabled !== true ||
  account.capabilities?.transfers !== "active"
) {
  return res.status(409).json({
    ok: false,
    code: "CONNECT_NOT_READY",
    error: "Stripe Connect account is not ready to receive rewards.",
  });
}
 const transfer = await stripe.transfers.create(
  {
    amount: reward.amount_cents,
    currency: reward.currency,
    destination: accountId,
    metadata: {
      tmkp_reward_id: String(reward.id),
      tmkp_user_id: String(req.userId),
      purpose: "live_test_referral_reward",
    },
  },
  {
    idempotencyKey: `tmkp-live-test-reward-${reward.id}`,
  }
);

await pool.query(
  `
  UPDATE referral_rewards
  SET status = 'transferred',
      stripe_transfer_id = $2,
      transferred_at = NOW(),
      updated_at = NOW()
  WHERE id = $1
    AND sponsor_user_id = $3
    AND status = 'pending';
  `,
  [reward.id, transfer.id, req.userId]
);

return res.json({
  ok: true,
  transferred: true,
  rewardId: reward.id,
  amountCents: reward.amount_cents,
  currency: reward.currency,
  transferId: transfer.id,
});
  } catch (err) {
    console.error("POST /connect/test-transfer error:", err);

    return res.status(500).json({
      ok: false,
      error: "Could not process test transfer.",
    });
  }
});
// -------------------------
// Endpoints básicos
// -------------------------
app.get("/health", (req, res) => {
res.json({ ok: true, ts: Date.now() });
});
// -------------------------
// Verificar Access Key (refid)
// -------------------------
app.get("/auth/validate-ref/:refid", async (req, res) => {
try {
const refid = String(req.params.refid || "").trim().toUpperCase();
if (!refid) {
return res.status(400).json({
ok: false,
valid: false,
error: "Missing refid"
});
}
const { rows } = await pool.query(
"SELECT id, full_name, refid FROM users WHERE UPPER(refid) = $1 LIMIT 1",
[refid]
);
if (rows.length === 0) {
return res.json({
ok: true,
valid: false
});
}
return res.json({
ok: true,
valid: true,
sponsor: {
id: rows[0].id,
full_name: rows[0].full_name,
refid: rows[0].refid
}
});
} catch (err) {
console.error("GET /auth/validate-ref/:refid error:", err);
return res.status(500).json({
ok: false,
valid: false,
error: "Server error"
});
}
});
// -------------------------
// AUTH: Crear cuenta
// Protegido por Stripe Checkout:
// - exige sessionId
// - confirma pago "paid"
// - bloquea reutilización del mismo pago
// - usa los datos del checkout guardados en PostgreSQL
// -------------------------
app.post("/auth/create-account", async (req, res) => {
const client = await pool.connect();
let transactionStarted = false;
try {
 const {
  sessionId,
  continuationToken,
  password,
  username: usernameRaw,
} = req.body || {};
if (
  !sessionId ||
  !String(sessionId).startsWith("cs_") ||
  !continuationToken
) { 
return res.status(400).json({
ok: false,
error: "Se requiere una sesión válida de Stripe para crear la cuenta.",
});
}
if (!password) {
return res.status(400).json({
ok: false,
error: "La contraseña es requerida.",
});
}
await client.query("BEGIN");
transactionStarted = true;
// Bloqueamos esta compra mientras se crea la cuenta.
// Esto evita que dos solicitudes simultáneas usen el mismo pago.
const paymentResult = await client.query(
`
SELECT
stripe_session_id,
email,
full_name,
phone,
country,
ref_code,
lang,
payment_status,
signup_used,
continuation_email_sent_at,
continuation_token_hash
FROM stripe_checkout_access 
WHERE stripe_session_id = $1
LIMIT 1
FOR UPDATE;
`,
[String(sessionId).trim()]
);
if (paymentResult.rows.length === 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(403).json({
ok: false,
error: "No se encontró una compra válida para esta sesión.",
});
}
const checkout = paymentResult.rows[0];
if (checkout.payment_status !== "paid") {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(402).json({
ok: false,
error: "El pago todavía no ha sido confirmado.",
});
}
if (checkout.signup_used) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(409).json({
ok: false,
error: "Este pago ya fue utilizado para crear una cuenta.",
});
}
const providedTokenHash = hashContinuationToken(continuationToken);
const storedTokenHash = String(checkout.continuation_token_hash || "");

const tokenMatches =
  /^[a-f0-9]{64}$/i.test(storedTokenHash) &&
  crypto.timingSafeEqual(
    Buffer.from(storedTokenHash, "hex"),
    Buffer.from(providedTokenHash, "hex")
  );

if (!tokenMatches) {
  await client.query("ROLLBACK");
  transactionStarted = false;

  return res.status(403).json({
    ok: false,
    code: "INVALID_VERIFICATION_TOKEN",
    error:
      checkout.lang === "en"
        ? "This verification link is no longer valid."
        : "Este enlace de verificación ya no es válido.",
  });
} 
if (!checkout.continuation_email_sent_at) {
  await client.query("ROLLBACK");
  transactionStarted = false;

  return res.status(403).json({
    ok: false,
    code: "EMAIL_VERIFICATION_REQUIRED",
    error:
      checkout.lang === "en"
        ? "Email verification is required to create your account."
        : "La verificación del correo es requerida para crear tu cuenta.",
  });
}

const verificationExpiresAt =
  new Date(checkout.continuation_email_sent_at).getTime() +
  48 * 60 * 60 * 1000;

if (Date.now() > verificationExpiresAt) {
  await client.query("ROLLBACK");
  transactionStarted = false;

  return res.status(410).json({
    ok: false,
    code: "VERIFICATION_LINK_EXPIRED",
    error:
      checkout.lang === "en"
        ? "This verification link has expired. Your payment remains confirmed."
        : "Este enlace de verificación ha expirado. Tu pago permanece confirmado.",
  });
} 
// Los datos de identidad/referral vienen del checkout confirmado,
// no del navegador.
const normalizedEmail = String(checkout.email || "").trim().toLowerCase();
const normalizedFullName = String(checkout.full_name || "").trim();
const normalizedPhone = normalizePhone(checkout.phone || "");
const normalizedCountry = String(checkout.country || "").trim().toUpperCase();
const referredby = checkout.ref_code
? String(checkout.ref_code).trim().toUpperCase()
: null;
const userLang =
String(checkout.lang || "").toLowerCase() === "en" ? "en" : "es";
if (!normalizedFullName || !normalizedEmail || !normalizedPhone) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(400).json({
ok: false,
error: "La compra no contiene todos los datos necesarios para crear la cuenta.",
});
}
let username =
(usernameRaw && String(usernameRaw).trim().toLowerCase()) ||
usernameFromEmail(normalizedEmail);
if (!username) {
username = `user${Date.now()}`;
}
// Verificar si ya existe email o username.
const existing = await client.query(
"SELECT id, email, username FROM users WHERE email = $1 OR username = $2 LIMIT 1",
[normalizedEmail, username]
);
if (existing.rows.length > 0) {
const conflict = existing.rows[0];
await client.query("ROLLBACK");
transactionStarted = false;
if (conflict.email === normalizedEmail) {
return res.status(409).json({
ok: false,
error: "Este correo ya está registrado.",
});
}
return res.status(409).json({
ok: false,
error: "Este nombre de usuario ya está en uso.",
});
}
const passwordHash = await bcrypt.hash(password, 10);
const refid = generateRefId(username, normalizedPhone);
const insertQuery = `
INSERT INTO users (
full_name,
email,
phone,
username,
password_hash,
refid,
referredby,
referrals,
is_admin,
lang,
country
)
VALUES ($1,$2,$3,$4,$5,$6,$7,0,false,$8,$9)
RETURNING *;
`;
const insertValues = [
normalizedFullName,
normalizedEmail,
normalizedPhone,
username,
passwordHash,
refid,
referredby,
userLang,
normalizedCountry || null,
];
const { rows } = await client.query(insertQuery, insertValues);
const newUser = rows[0];
// Crédito al patrocinador dentro de la misma transacción.
// Guardamos el estado actualizado para detectar únicamente el PRIMER referido.
let sponsorAfterReferral = null;

if (referredby) {
const sponsorResult = await client.query(
`
UPDATE users
SET referrals = COALESCE(referrals, 0) + 1
WHERE UPPER(refid) = $1
RETURNING id, email, full_name, lang, referrals;
`,
[referredby]
);

if (sponsorResult.rows.length > 0) {
sponsorAfterReferral = sponsorResult.rows[0];
}
} 
// Reserve the original purchase email as a permanent alias for
// this membership, independent of future login-email changes.
await client.query(
`
INSERT INTO account_email_history (user_id, email)
VALUES ($1, LOWER($2))
ON CONFLICT DO NOTHING;
`,
[newUser.id, normalizedEmail]
);
// Consume the purchase and permanently link it to the new user_id.
// From this point forward the purchase belongs to the account even if
// the member later changes the login email in Settings.
const consumeResult = await client.query(
`
UPDATE stripe_checkout_access
SET user_id = $2,
signup_used = TRUE,
signup_used_at = NOW(),
updated_at = NOW()
WHERE stripe_session_id = $1
AND signup_used = FALSE;
`,
[String(sessionId).trim(), newUser.id]
);
if (consumeResult.rowCount !== 1) {
throw new Error("Stripe Checkout Session could not be consumed.");
}
await client.query("COMMIT");
transactionStarted = false;
// Email especial: solamente cuando el patrocinador recibe su PRIMER referido.
// Se envía después del COMMIT para que una falla de email nunca deshaga
// la cuenta recién creada ni el crédito del referido.
if (
sponsorAfterReferral &&
Number(sponsorAfterReferral.referrals || 0) === 1 &&
sponsorAfterReferral.email
) {
try {
const sponsorLang = sponsorAfterReferral.lang === "en" ? "en" : "es";
const dashboardUrl = "https://themasterkeyprogram.com/dashboard.html";

const subject =
sponsorLang === "en"
? "We received your first referral! \u{1F389}"
: "¡Recibimos tu primer referido! \u{1F389}";

const html =
sponsorLang === "en"
? `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.65;max-width:640px;margin:0 auto;">
<h2 style="color:#111;">The Master Key Program</h2>
<p><strong>We received your first referral! \u{1F389}</strong></p>
<p>Your first referral has been recorded successfully and is now under review.</p>
<p>The review process may take <strong>3–7 business days</strong>. Once the referral is approved, you will receive a confirmation email.</p>
<p><strong>Important:</strong> this email confirms that the referral was received. It does not mean that a reward has been approved yet.</p>
<p>To avoid sending you an email for every referral, after this first notification you will receive a <strong>weekly summary only when there is activity</strong> on your referral account.</p>
<p>You can also check your referrals and their status at any time from your Dashboard.</p>
<p>
<a href="${dashboardUrl}"
style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:999px;font-weight:700;">
View My Dashboard
</a>
</p>
<p>Thank you for sharing The Master Key Program.</p>
</div>
`
: `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.65;max-width:640px;margin:0 auto;">
<h2 style="color:#111;">The Master Key Program</h2>
<p><strong>¡Recibimos tu primer referido! \u{1F389}</strong></p>
<p>Tu primer referido ha sido registrado correctamente y ahora se encuentra bajo revisión.</p>
<p>El proceso de revisión puede tomar de <strong>3 a 7 días hábiles</strong>. Cuando el referido sea aprobado, recibirás un email de confirmación.</p>
<p><strong>Importante:</strong> este correo confirma que el referido fue recibido. Todavía no significa que una recompensa haya sido aprobada.</p>
<p>Para evitar enviarte un correo por cada referido, después de este primer aviso recibirás un <strong>resumen semanal únicamente cuando haya actividad</strong> en tu cuenta de referidos.</p>
<p>También puedes consultar tus referidos y su estado en cualquier momento desde tu Dashboard.</p>
<p>
<a href="${dashboardUrl}"
style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:999px;font-weight:700;">
Ver mi Dashboard
</a>
</p>
<p>Gracias por compartir The Master Key Program.</p>
</div>
`;

const emailText =
sponsorLang === "en"
? `We received your first referral! \u{1F389}
Your first referral has been recorded and is under review.
The review process may take 3–7 business days.
Once approved, you will receive a confirmation email.
This message confirms receipt only; it does not mean that a reward has been approved yet.
After this first notice, you will receive a weekly summary only when there is activity.
You can also check your referral status anytime from your Dashboard:
${dashboardUrl}`
: `¡Recibimos tu primer referido! \u{1F389}
Tu primer referido ha sido registrado y está bajo revisión.
El proceso puede tomar de 3 a 7 días hábiles.
Cuando sea aprobado, recibirás un email de confirmación.
Este mensaje confirma únicamente la recepción; todavía no significa que una recompensa haya sido aprobada.
Después de este primer aviso, recibirás un resumen semanal únicamente cuando haya actividad.
También puedes consultar el estado de tus referidos en cualquier momento desde tu Dashboard:
${dashboardUrl}`;

const firstReferralEmail = await resend.emails.send({
from: "The Master Key <support@themasterkeyprogram.com>",
to: sponsorAfterReferral.email,
subject,
html,
text: emailText,
});

if (firstReferralEmail && firstReferralEmail.error) {
console.error("First-referral email failed:", firstReferralEmail.error);
}
} catch (firstReferralEmailErr) {
console.error("First-referral email failed:", firstReferralEmailErr);
}
} 
const token = createToken(newUser);
const userResp = buildUserResponse(newUser);
return res.status(201).json({
ok: true,
token,
user: userResp,
});
} catch (err) {
if (transactionStarted) {
try {
await client.query("ROLLBACK");
} catch (rollbackErr) {
console.error("ROLLBACK /auth/create-account error:", rollbackErr);
}
}
console.error("POST /auth/create-account error:", err);
// PostgreSQL unique_violation.
if (err && err.code === "23505") {
return res.status(409).json({
ok: false,
error: "El correo, usuario o código personal ya está registrado.",
});
}
return res.status(500).json({
ok: false,
error: "Server error",
});
} finally {
client.release();
}
});
// -------------------------
// AUTH: Login
// -------------------------
app.post("/auth/login", async (req, res) => {
try {
const { email, password } = req.body || {};
if (!email || !password) {
return res
.status(400)
.json({ ok: false, error: "Email y contraseña son requeridos" });
}
const normalizedEmail = String(email).trim().toLowerCase();
const { rows } = await pool.query(
"SELECT * FROM users WHERE email = $1 LIMIT 1",
[normalizedEmail]
);
if (rows.length === 0) {
return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
}
const user = rows[0];
const passwordMatch = await bcrypt.compare(password, user.password_hash);
if (!passwordMatch) {
return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
}
const token = createToken(user);
const userResp = buildUserResponse(user);
return res.json({
ok: true,
token,
user: userResp,
});
} catch (err) {
console.error("POST /auth/login error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// /me: perfil del usuario logueado
// -------------------------
app.get("/me", authMiddleware, async (req, res) => {
try {
const { userId } = req;
const { rows } = await pool.query(
"SELECT * FROM users WHERE id = $1 LIMIT 1",
[userId]
);
if (rows.length === 0) {
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const user = rows[0];
const userResp = buildUserResponse(user);
return res.json({
ok: true,
user: userResp,
});
} catch (err) {
console.error("GET /me error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// REFERRALS: resumen real del miembro
// -------------------------
app.get("/referrals/summary", authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query(
      `
      SELECT refid
      FROM users
      WHERE id = $1
      LIMIT 1;
      `,
      [req.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Usuario no encontrado",
      });
    }

    const refCode = String(userResult.rows[0].refid || "")
      .trim()
      .toUpperCase();

    if (!refCode) {
      return res.json({
        ok: true,
        total: 0,
        pending: 0,
        qualified: 0,
      });
    }

    const summaryResult = await pool.query(
      `
      SELECT
         COUNT(*)::int AS total,

        COUNT(*) FILTER (
          WHERE referral_status = 'pending'
        )::int AS pending,

        COUNT(*) FILTER (
          WHERE referral_status = 'qualified'
        )::int AS qualified

      FROM stripe_checkout_access
      WHERE UPPER(ref_code) = $1
        AND payment_status = 'paid'
        AND signup_used = TRUE
        AND user_id IS NOT NULL;
      `,
      [refCode]
    );

    const summary = summaryResult.rows[0] || {};

    return res.json({
      ok: true,
      total: Number(summary.total || 0),
      pending: Number(summary.pending || 0),
      qualified: Number(summary.qualified || 0),
    });
  } catch (err) {
    console.error("GET /referrals/summary error:", err);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});
// -------------------------
// REFERRALS: actividad del miembro
// -------------------------
app.get("/referrals/activity", authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query(
      `
      SELECT refid
      FROM users
      WHERE id = $1
      LIMIT 1;
      `,
      [req.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Usuario no encontrado",
      });
    }

    const refCode = String(userResult.rows[0].refid || "")
      .trim()
      .toUpperCase();

    if (!refCode) {
      return res.json({
        ok: true,
        referrals: [],
      });
    }

    const activityResult = await pool.query(
      `
      SELECT
        email,
        referral_status,
        COALESCE(signup_used_at, created_at) AS joined_at
      FROM stripe_checkout_access
      WHERE UPPER(ref_code) = $1
        AND payment_status = 'paid'
        AND signup_used = TRUE
        AND user_id IS NOT NULL
        AND referral_status IN ('pending', 'qualified')
      ORDER BY COALESCE(signup_used_at, created_at) DESC
      LIMIT 100;
      `,
      [refCode]
    );

    const referrals = activityResult.rows.map((row) => {
      const rawEmail = String(row.email || "").trim().toLowerCase();
      const at = rawEmail.indexOf("@");

      let maskedEmail = rawEmail;

      if (at > 0) {
        const local = rawEmail.slice(0, at);
        const domain = rawEmail.slice(at + 1);

        maskedEmail = `${local.slice(0, 1)}***@${domain}`;
      }

      return {
        email: maskedEmail,
        status: row.referral_status,
        joinedAt: row.joined_at,
      };
    });

    return res.json({
      ok: true,
      referrals,
    });
  } catch (err) {
    console.error("GET /referrals/activity error:", err);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});
// =========================================================
// TMKP CONTENT PROGRESS - STEP 2
// Member progress endpoints.
// Requires STEP 1 above.
// =========================================================
function normalizeContentKey(value) {
return String(value || "").trim().toLowerCase();
}
function progressRowToResponse(row) {
const totalUnits = Number(row.total_units || 0);
const currentUnit = Math.min(
Math.max(Number(row.current_unit || 0), 0),
totalUnits || Number.MAX_SAFE_INTEGER
);
const percent =
totalUnits > 0
? Math.min(100, Math.round((currentUnit / totalUnits) * 100))
: 0;
return {
contentKey: row.content_key,
contentType: row.content_type,
titleEs: row.title_es,
titleEn: row.title_en,
totalUnits,
currentUnit,
 resumeUnit: Number(row.resume_unit || 0),
resumeUpdatedAt: row.resume_updated_at || null,
percent,
status: row.effective_status || row.status || "locked",
unlockedAt: row.unlocked_at || null,
startedAt: row.started_at || null,
completedAt: row.completed_at || null,
updatedAt: row.progress_updated_at || null,
};
}
async function getUserContentProgress(userId, db = pool) {
const { rows } = await db.query(
`
SELECT
c.content_key,
c.content_type,
c.title_es,
c.title_en,
c.total_units,
c.sort_order,
COALESCE(p.current_unit, 0)::int AS current_unit,
COALESCE(p.resume_unit, 0)::int AS resume_unit,
p.resume_updated_at,
CASE
WHEN p.status IS NOT NULL THEN p.status
WHEN c.content_key = 'ebook_abundance' THEN 'unlocked'
ELSE 'locked'
END AS effective_status,
p.unlocked_at,
p.started_at,
p.completed_at,
p.updated_at AS progress_updated_at
FROM content_catalog AS c
LEFT JOIN user_content_progress AS p
ON p.content_key = c.content_key
AND p.user_id = $1
WHERE c.is_active = TRUE
ORDER BY c.sort_order ASC, c.content_key ASC;
`,
[userId]
);
return rows.map(progressRowToResponse);
}
// GET /progress
// Returns the official progress for the logged-in member.
app.get("/progress", authMiddleware, async (req, res) => {
try {
await contentProgressReady;
const progress = await getUserContentProgress(req.userId);
return res.json({
ok: true,
progress,
});
} catch (err) {
console.error("GET /progress error:", err);
return res.status(500).json({
ok: false,
error: "Server error",
});
}
});
// POST /progress/resume
// Guarda la última sección del E-Book que el miembro abrió.
// NO marca esa sección como completada.
app.post("/progress/resume", authMiddleware, async (req, res) => {
  try {
    await contentProgressReady;

    const userId = req.userId;
    const contentKey = normalizeContentKey(req.body?.contentKey);
    const resumeUnit = Number(req.body?.resumeUnit);

    if (!["ebook_abundance", "truth_path"].includes(contentKey)) {
  return res.status(400).json({
    ok: false,
    code: "UNSUPPORTED_CONTENT",
    error: "Resume tracking is not enabled for this content",
  });
}

if (!Number.isInteger(resumeUnit)) {
  return res.status(400).json({
    ok: false,
    error: "integer resumeUnit is required",
  });
}

const catalogResult = await pool.query(
  `
    SELECT total_units
    FROM content_catalog
    WHERE content_key = $1
      AND is_active = TRUE
    LIMIT 1;
  `,
  [contentKey]
);

if (catalogResult.rows.length === 0) {
  return res.status(404).json({
    ok: false,
    code: "CONTENT_NOT_FOUND",
    error: "Content not found",
  });
}

const totalUnits = Number(catalogResult.rows[0].total_units);

if (contentKey === "truth_path") {
  const accessResult = await pool.query(
    `
      SELECT current_unit, status
      FROM user_content_progress
      WHERE user_id = $1::bigint
        AND content_key = 'truth_path'
      LIMIT 1;
    `,
    [userId]
  );

  const access = accessResult.rows[0] || null;
  const allowedStatuses = ["unlocked", "in_progress", "completed"];

  if (!access || !allowedStatuses.includes(access.status)) {
    return res.status(403).json({
      ok: false,
      code: "CONTENT_LOCKED",
      error: "The Truth Path is locked",
    });
  }

  const currentUnit = Number(access.current_unit || 0);
  const maxResumeUnit = Math.min(totalUnits, currentUnit + 1);

  if (resumeUnit > maxResumeUnit) {
    return res.status(409).json({
      ok: false,
      code: "RESUME_OUT_OF_SEQUENCE",
      error: "Resume position is ahead of the allowed Truth Path day",
      currentUnit,
      maxResumeUnit,
      requestedResumeUnit: resumeUnit,
    });
  }
}

    if (resumeUnit < 0 || resumeUnit > totalUnits) {
      return res.status(400).json({
        ok: false,
        code: "INVALID_RESUME_UNIT",
        error: `resumeUnit must be between 0 and ${totalUnits}`,
      });
    }

    await pool.query(
      `
        INSERT INTO user_content_progress (
          user_id,
          content_key,
          current_unit,
          status,
          unlocked_at,
          started_at,
          resume_unit,
          resume_updated_at,
          updated_at
        )
        VALUES (
          $1::bigint,
          $2::text,
          0,
          'in_progress',
          NOW(),
          NOW(),
          $3::integer,
          NOW(),
          NOW()
        )
        ON CONFLICT (user_id, content_key)
        DO UPDATE SET
          resume_unit = EXCLUDED.resume_unit,
          resume_updated_at = NOW()
        RETURNING *;
      `,
      [userId, contentKey, resumeUnit]
    );

    const progress = await getUserContentProgress(userId);
    const item =
      progress.find((p) => p.contentKey === contentKey) || null;

    return res.json({
      ok: true,
      item,
    });
  } catch (err) {
    console.error("POST /progress/resume error:", err);
    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});
// POST /progress/update
// Saves one completed unit. Progress can only move forward in sequence.
app.post("/progress/update", authMiddleware, async (req, res) => {
const client = await pool.connect();
let transactionStarted = false;
try {
await contentProgressReady;
const userId = req.userId;
const contentKey = normalizeContentKey(req.body?.contentKey);
const unit = Number(req.body?.unit);
if (!contentKey || !Number.isInteger(unit)) {
return res.status(400).json({
ok: false,
error: "contentKey and integer unit are required",
});
}
await client.query("BEGIN");
transactionStarted = true;
const catalogResult = await client.query(
`
SELECT
content_key,
total_units
FROM content_catalog
WHERE content_key = $1
AND is_active = TRUE
LIMIT 1
FOR SHARE;
`,
[contentKey]
);
if (catalogResult.rows.length === 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(404).json({
ok: false,
code: "CONTENT_NOT_FOUND",
error: "Content not found",
});
}
const totalUnits = Number(catalogResult.rows[0].total_units);
if (unit < 1 || unit > totalUnits) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(400).json({
ok: false,
code: "INVALID_PROGRESS_UNIT",
error: `Unit must be between 1 and ${totalUnits}`,
});
}
const progressResult = await client.query(
`
SELECT
user_id,
content_key,
current_unit,
status,
unlocked_at,
started_at,
completed_at,
updated_at
FROM user_content_progress
WHERE user_id = $1
AND content_key = $2
LIMIT 1
FOR UPDATE;
`,
[userId, contentKey]
);
let existing = progressResult.rows[0] || null;
// The first E-Book is included with membership and is implicitly unlocked.
// Other programs must first be unlocked by a server-side rule.
if (!existing && contentKey !== "ebook_abundance") {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(403).json({
ok: false,
code: "CONTENT_LOCKED",
error: "This content is locked",
});
}
if (existing && existing.status === "locked") {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(403).json({
ok: false,
code: "CONTENT_LOCKED",
error: "This content is locked",
});
}
const currentUnit = existing
? Number(existing.current_unit || 0)
: 0;
// Repeating the same/older completed unit is harmless.
// Jumping several units forward is rejected.
if (unit > currentUnit + 1) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(409).json({
ok: false,
code: "PROGRESS_OUT_OF_SEQUENCE",
error: "Progress must be completed in sequence",
currentUnit,
requestedUnit: unit,
});
}
if (!existing) {
 const insertResult = await client.query(
`
INSERT INTO user_content_progress (
user_id,
content_key,
current_unit,
status,
unlocked_at,
started_at,
completed_at,
updated_at
)
VALUES (
$1::bigint,
$2::text,
$3::integer,
CASE
WHEN $3::integer >= $4::integer THEN 'completed'
ELSE 'in_progress'
END,
NOW(),
NOW(),
CASE
WHEN $3::integer >= $4::integer THEN NOW()
ELSE NULL
END,
NOW()
)
ON CONFLICT (user_id, content_key)
DO NOTHING
RETURNING *;
`,
[userId, contentKey, unit, totalUnits]
);
if (insertResult.rows.length > 0) {
existing = insertResult.rows[0];
} else {
// Extremely rare simultaneous request: lock the row created by
// the other request and continue safely.
const retryResult = await client.query(
`
SELECT *
FROM user_content_progress
WHERE user_id = $1
AND content_key = $2
LIMIT 1
FOR UPDATE;
`,
[userId, contentKey]
);
existing = retryResult.rows[0] || null;
}
}
if (existing) {
const savedUnit = Number(existing.current_unit || 0);
if (unit > savedUnit + 1) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(409).json({
ok: false,
code: "PROGRESS_OUT_OF_SEQUENCE",
error: "Progress must be completed in sequence",
currentUnit: savedUnit,
requestedUnit: unit,
});
}
if (unit > savedUnit) {
 const updateResult = await client.query(
`
UPDATE user_content_progress
SET current_unit = $3::integer,
status = CASE
WHEN $3::integer >= $4::integer THEN 'completed'
ELSE 'in_progress'
END,
unlocked_at = COALESCE(unlocked_at, NOW()),
started_at = COALESCE(started_at, NOW()),
completed_at = CASE
WHEN $3::integer >= $4::integer THEN COALESCE(completed_at, NOW())
ELSE completed_at
END,
updated_at = NOW()
WHERE user_id = $1::bigint
AND content_key = $2::text
RETURNING *;
`,
[userId, contentKey, unit, totalUnits]
);
existing = updateResult.rows[0];
}
}
await client.query("COMMIT");
transactionStarted = false;
const progress = await getUserContentProgress(userId);
const item =
progress.find((p) => p.contentKey === contentKey) || null;
return res.json({
ok: true,
item,
progress,
});
} catch (err) {
if (transactionStarted) {
try {
await client.query("ROLLBACK");
} catch (_) {}
}
console.error("POST /progress/update error:", err);
return res.status(500).json({
ok: false,
error: "Server error",
});
} finally {
client.release();
}
});
// POST /progress/truth-path/quiz
// Scores the WebBook comprehension quiz on the server.
// Passing the quiz unlocks The Truth Path for this user_id.
app.post("/progress/truth-path/quiz", authMiddleware, async (req, res) => {
const client = await pool.connect();
let transactionStarted = false;
try {
await contentProgressReady;
const userId = req.userId;
const answers = req.body?.answers || {};
const ANSWERS = {
q1: "C",
q2: "C",
q3: "B",
q4: "B",
q5: "B",
q6: "C",
q7: "C",
};
const TOTAL = 7;
const PASS = 6;
const normalizedAnswers = {};
for (let i = 1; i <= TOTAL; i++) {
const key = `q${i}`;
const value = String(answers[key] || "").trim().toUpperCase();
if (!["A", "B", "C", "D"].includes(value)) {
return res.status(400).json({
ok: false,
code: "QUIZ_INCOMPLETE",
error: "All quiz questions must be answered.",
});
}
normalizedAnswers[key] = value;
}
await client.query("BEGIN");
transactionStarted = true;
// The quiz can unlock TTP only after the WebBook is officially complete.
const ebookResult = await client.query(
`
SELECT
p.current_unit,
p.status,
c.total_units
FROM user_content_progress AS p
JOIN content_catalog AS c
ON c.content_key = p.content_key
WHERE p.user_id = $1::bigint
AND p.content_key = 'ebook_abundance'
AND c.is_active = TRUE
LIMIT 1
FOR UPDATE;
`,
[userId]
);
if (ebookResult.rows.length === 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(403).json({
ok: false,
code: "EBOOK_NOT_COMPLETED",
error: "Complete the WebBook before taking this quiz.",
});
}
const ebook = ebookResult.rows[0];
const ebookCurrentUnit = Number(ebook.current_unit || 0);
const ebookTotalUnits = Number(ebook.total_units || 0);
if (
ebookCurrentUnit < ebookTotalUnits ||
ebook.status !== "completed"
) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(403).json({
ok: false,
code: "EBOOK_NOT_COMPLETED",
error: "Complete the WebBook before unlocking The Truth Path.",
currentUnit: ebookCurrentUnit,
totalUnits: ebookTotalUnits,
});
}
let score = 0;
for (const key of Object.keys(ANSWERS)) {
if (normalizedAnswers[key] === ANSWERS[key]) {
score++;
}
}
// A failed attempt does not change TTP access.
if (score < PASS) {
await client.query("COMMIT");
transactionStarted = false;
return res.json({
ok: true,
passed: false,
score,
total: TOTAL,
required: PASS,
});
}
// Passing is idempotent:
// - locked/not-yet-created -> unlocked
// - already unlocked/in_progress/completed -> keep existing status
await client.query(
`
INSERT INTO user_content_progress (
user_id,
content_key,
current_unit,
status,
unlocked_at,
started_at,
completed_at,
resume_unit,
resume_updated_at,
updated_at
)
VALUES (
$1::bigint,
'truth_path',
0,
'unlocked',
NOW(),
NULL,
NULL,
0,
NULL,
NOW()
)
ON CONFLICT (user_id, content_key)
DO UPDATE SET
status = CASE
WHEN user_content_progress.status = 'locked'
THEN 'unlocked'
ELSE user_content_progress.status
END,
unlocked_at = COALESCE(
user_content_progress.unlocked_at,
NOW()
),
updated_at = NOW();
`,
[userId]
);
await client.query("COMMIT");
transactionStarted = false;
const progress = await getUserContentProgress(userId);
const truthPath =
progress.find((p) => p.contentKey === "truth_path") || null;
return res.json({
ok: true,
passed: true,
score,
total: TOTAL,
required: PASS,
truthPath,
progress,
});
} catch (err) {
if (transactionStarted) {
try {
await client.query("ROLLBACK");
} catch (_) {}
}
console.error("POST /progress/truth-path/quiz error:", err);
return res.status(500).json({
ok: false,
error: "Server error",
});
} finally {
client.release();
}
});
// =========================================================
// END TMKP CONTENT PROGRESS - STEP 2
// =========================================================
// -------------------------
// Cuenta: actualizar perfil (email / phone)
// -------------------------
app.post("/account/update-profile", authMiddleware, async (req, res) => {
try {
const { userId } = req;
const { fullName, email, phone, country, lang } = req.body || {};
const currentResult = await pool.query(
"SELECT * FROM users WHERE id = $1 LIMIT 1",
[userId]
);
if (currentResult.rows.length === 0) {
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const currentUser = currentResult.rows[0];
// Email is never changed through this generic profile endpoint.
// A different email must use the password + verification-code flow.
if (email) {
const requestedEmail = normalizeEmail(email);
const currentEmail = normalizeEmail(currentUser.email);
if (requestedEmail && requestedEmail !== currentEmail) {
return res.status(409).json({
ok: false,
code: "EMAIL_REQUIRES_VERIFICATION",
error:
currentUser.lang === "en"
? "Email changes require password confirmation and verification."
: "Los cambios de email requieren contraseña y verificación.",
});
}
}
const normalizedFullName =
fullName !== undefined ? String(fullName || "").trim() : null;
const normalizedPhone =
phone !== undefined ? normalizePhone(phone) : null;
const normalizedCountry =
country !== undefined
? String(country || "").trim().toUpperCase().slice(0, 8)
: null;
const normalizedLang =
lang !== undefined ? (String(lang).toLowerCase() === "en" ? "en" : "es") : null;
if (fullName !== undefined && !normalizedFullName) {
return res.status(400).json({
ok: false,
error:
currentUser.lang === "en"
? "Full name is required."
: "El nombre completo es requerido.",
});
}
const { rows } = await pool.query(
`
UPDATE users
SET full_name = COALESCE($1, full_name),
phone = COALESCE($2, phone),
country = COALESCE($3, country),
lang = COALESCE($4, lang)
WHERE id = $5
RETURNING *;
`,
[
normalizedFullName,
normalizedPhone,
normalizedCountry,
normalizedLang,
userId,
]
);
return res.json({
ok: true,
user: buildUserResponse(rows[0]),
});
} catch (err) {
console.error("POST /account/update-profile error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// Cuenta: solicitar cambio de email
// Requiere contraseña actual y envía un código al NUEVO correo.
// -------------------------
app.post("/account/request-email-change", authMiddleware, async (req, res) => {
try {
await accountSecurityReady;
const { userId } = req;
const newEmail = normalizeEmail(req.body?.newEmail);
const currentPassword = String(req.body?.currentPassword || "");
const { rows } = await pool.query(
"SELECT * FROM users WHERE id = $1 LIMIT 1",
[userId]
);
if (rows.length === 0) {
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const user = rows[0];
const language = user.lang === "en" ? "en" : "es";
if (!newEmail || !isValidEmail(newEmail)) {
return res.status(400).json({
ok: false,
error: language === "en" ? "Enter a valid email." : "Ingresa un email válido.",
});
}
if (!currentPassword) {
return res.status(400).json({
ok: false,
error:
language === "en"
? "Your current password is required."
: "Tu contraseña actual es requerida.",
});
}
if (newEmail === normalizeEmail(user.email)) {
return res.status(400).json({
ok: false,
error:
language === "en"
? "That is already your current email."
: "Ese ya es tu email actual.",
});
}
const passwordMatches = await bcrypt.compare(
currentPassword,
user.password_hash
);
if (!passwordMatches) {
return res.status(401).json({
ok: false,
error:
language === "en"
? "Current password is incorrect."
: "La contraseña actual es incorrecta.",
});
}
// Current account conflict.
const userConflict = await pool.query(
`
SELECT id
FROM users
WHERE LOWER(email) = LOWER($1)
AND id <> $2
LIMIT 1
`,
[newEmail, userId]
);
if (userConflict.rows.length > 0) {
return res.status(409).json({
ok: false,
error:
language === "en"
? "That email is already being used by another account."
: "Ese email ya está siendo utilizado por otra cuenta.",
});
}
// Historical account alias conflict.
const historyConflict = await pool.query(
`
SELECT user_id
FROM account_email_history
WHERE LOWER(email) = LOWER($1)
AND user_id <> $2
LIMIT 1
`,
[newEmail, userId]
);
if (historyConflict.rows.length > 0) {
return res.status(409).json({
ok: false,
error:
language === "en"
? "That email is already associated with another membership."
: "Ese email ya está asociado con otra membresía.",
});
}
// Do not absorb an unfinished paid purchase that belongs to another
// registration flow.
const paymentConflict = await pool.query(
`
SELECT user_id
FROM stripe_checkout_access
WHERE LOWER(email) = LOWER($1)
AND payment_status = 'paid'
AND (user_id IS NULL OR user_id <> $2)
LIMIT 1
`,
[newEmail, userId]
).catch(() => ({ rows: [] }));
if (paymentConflict.rows.length > 0) {
return res.status(409).json({
ok: false,
error:
language === "en"
? "That email is already associated with another purchase."
: "Ese email ya está asociado con otra compra.",
});
}
// Simple resend cooldown.
const existingRequest = await pool.query(
`
SELECT new_email, last_sent_at
FROM email_change_requests
WHERE user_id = $1
LIMIT 1
`,
[userId]
);
if (existingRequest.rows.length > 0) {
const row = existingRequest.rows[0];
const lastSent = row.last_sent_at ? new Date(row.last_sent_at).getTime() : 0;
const secondsAgo = Math.floor((Date.now() - lastSent) / 1000);
if (
normalizeEmail(row.new_email) === newEmail &&
secondsAgo >= 0 &&
secondsAgo < EMAIL_CHANGE_RESEND_SECONDS
) {
return res.status(429).json({
ok: false,
error:
language === "en"
? "Please wait a moment before requesting another code."
: "Espera un momento antes de solicitar otro código.",
});
}
}
const code = crypto.randomInt(100000, 1000000).toString();
const codeHash = hashEmailChangeCode(code);
const expiresAt = new Date(
Date.now() + EMAIL_CHANGE_TTL_MINUTES * 60 * 1000
);
await pool.query(
`
INSERT INTO email_change_requests (
user_id,
new_email,
code_hash,
attempts,
expires_at,
last_sent_at,
created_at,
updated_at
)
VALUES ($1,$2,$3,0,$4,NOW(),NOW(),NOW())
ON CONFLICT (user_id)
DO UPDATE SET
new_email = EXCLUDED.new_email,
code_hash = EXCLUDED.code_hash,
attempts = 0,
expires_at = EXCLUDED.expires_at,
last_sent_at = NOW(),
updated_at = NOW()
`,
[userId, newEmail, codeHash, expiresAt]
);
const subject =
language === "en"
? "Verify your new email"
: "Verifica tu nuevo email";
const html =
language === "en"
? `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6">
<h2>The Master Key</h2>
<p>Use this verification code to confirm your new email:</p>
<div style="font-size:30px;font-weight:700;letter-spacing:8px;margin:24px 0;">${code}</div>
<p>This code expires in ${EMAIL_CHANGE_TTL_MINUTES} minutes.</p>
<p>If you did not request this change, you can ignore this email.</p>
</div>
`
: `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6">
<h2>The Master Key</h2>
<p>Usa este código de verificación para confirmar tu nuevo email:</p>
<div style="font-size:30px;font-weight:700;letter-spacing:8px;margin:24px 0;">${code}</div>
<p>Este código expira en ${EMAIL_CHANGE_TTL_MINUTES} minutos.</p>
<p>Si tú no solicitaste este cambio, puedes ignorar este correo.</p>
</div>
`;
try {
await resend.emails.send({
from: "The Master Key <support@themasterkeyprogram.com>",
to: newEmail,
subject,
html,
});
} catch (emailErr) {
await pool.query(
"DELETE FROM email_change_requests WHERE user_id = $1 AND LOWER(new_email) = LOWER($2)",
[userId, newEmail]
).catch(() => {});
throw emailErr;
}
return res.json({
ok: true,
verificationRequired: true,
expiresInMinutes: EMAIL_CHANGE_TTL_MINUTES,
newEmail,
});
} catch (err) {
console.error("POST /account/request-email-change error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// Cuenta: confirmar cambio de email
// -------------------------
app.post("/account/confirm-email-change", authMiddleware, async (req, res) => {
const client = await pool.connect();
let transactionStarted = false;
try {
await accountSecurityReady;
const { userId } = req;
const code = String(req.body?.code || "").trim();
if (!/^\d{6}$/.test(code)) {
return res.status(400).json({
ok: false,
error: "Invalid verification code.",
});
}
await client.query("BEGIN");
transactionStarted = true;
const userResult = await client.query(
"SELECT * FROM users WHERE id = $1 LIMIT 1 FOR UPDATE",
[userId]
);
if (userResult.rows.length === 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const user = userResult.rows[0];
const language = user.lang === "en" ? "en" : "es";
const requestResult = await client.query(
`
SELECT *
FROM email_change_requests
WHERE user_id = $1
LIMIT 1
FOR UPDATE
`,
[userId]
);
if (requestResult.rows.length === 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(400).json({
ok: false,
error:
language === "en"
? "No email change is waiting for verification."
: "No hay un cambio de email pendiente de verificación.",
});
}
const request = requestResult.rows[0];
if (new Date(request.expires_at).getTime() <= Date.now()) {
await client.query(
"DELETE FROM email_change_requests WHERE user_id = $1",
[userId]
);
await client.query("COMMIT");
transactionStarted = false;
return res.status(400).json({
ok: false,
error:
language === "en"
? "The verification code has expired. Request a new one."
: "El código de verificación expiró. Solicita uno nuevo.",
});
}
if (Number(request.attempts || 0) >= EMAIL_CHANGE_MAX_ATTEMPTS) {
await client.query(
"DELETE FROM email_change_requests WHERE user_id = $1",
[userId]
);
await client.query("COMMIT");
transactionStarted = false;
return res.status(429).json({
ok: false,
error:
language === "en"
? "Too many attempts. Request a new verification code."
: "Demasiados intentos. Solicita un nuevo código.",
});
}
const submittedHash = hashEmailChangeCode(code);
if (submittedHash !== request.code_hash) {
await client.query(
`
UPDATE email_change_requests
SET attempts = attempts + 1,
updated_at = NOW()
WHERE user_id = $1
`,
[userId]
);
await client.query("COMMIT");
transactionStarted = false;
return res.status(400).json({
ok: false,
error:
language === "en"
? "Incorrect verification code."
: "Código de verificación incorrecto.",
});
}
const newEmail = normalizeEmail(request.new_email);
// Re-check conflicts at confirmation time.
const conflict = await client.query(
`
SELECT id
FROM users
WHERE LOWER(email) = LOWER($1)
AND id <> $2
LIMIT 1
`,
[newEmail, userId]
);
if (conflict.rows.length > 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(409).json({
ok: false,
error:
language === "en"
? "That email is already being used by another account."
: "Ese email ya está siendo utilizado por otra cuenta.",
});
}
const historyConflict = await client.query(
`
SELECT user_id
FROM account_email_history
WHERE LOWER(email) = LOWER($1)
AND user_id <> $2
LIMIT 1
`,
[newEmail, userId]
);
if (historyConflict.rows.length > 0) {
await client.query("ROLLBACK");
transactionStarted = false;
return res.status(409).json({
ok: false,
error:
language === "en"
? "That email is already associated with another membership."
: "Ese email ya está asociado con otra membresía.",
});
}
// Preserve both the original/previous email and the new email as
// permanent aliases for this membership. Stripe's historical receipt
// email is intentionally not rewritten.
await client.query(
`
INSERT INTO account_email_history (user_id, email)
VALUES ($1, LOWER($2))
ON CONFLICT DO NOTHING
`,
[userId, user.email]
);
await client.query(
`
INSERT INTO account_email_history (user_id, email)
VALUES ($1, LOWER($2))
ON CONFLICT DO NOTHING
`,
[userId, newEmail]
);
const updatedResult = await client.query(
`
UPDATE users
SET email = $1
WHERE id = $2
RETURNING *;
`,
[newEmail, userId]
);
await client.query(
"DELETE FROM email_change_requests WHERE user_id = $1",
[userId]
);
await client.query("COMMIT");
transactionStarted = false;
// Security notice to the previous email. Failure to send this notice
// does not undo a change that was already verified and committed.
const oldEmail = normalizeEmail(user.email);
if (oldEmail && oldEmail !== newEmail) {
const noticeSubject =
language === "en"
? "Your TMKP email was changed"
: "Tu email de TMKP fue cambiado";
const noticeHtml =
language === "en"
? `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6">
<h2>The Master Key</h2>
<p>The email on your account was changed to <strong>${newEmail}</strong>.</p>
<p>If you did not make this change, contact support immediately.</p>
</div>
`
: `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6">
<h2>The Master Key</h2>
<p>El email de tu cuenta fue cambiado a <strong>${newEmail}</strong>.</p>
<p>Si tú no realizaste este cambio, contacta a soporte inmediatamente.</p>
</div>
`;
resend.emails.send({
from: "The Master Key <support@themasterkeyprogram.com>",
to: oldEmail,
subject: noticeSubject,
html: noticeHtml,
}).catch((noticeErr) => {
console.error("Email-change old-address notice failed:", noticeErr);
});
}
return res.json({
ok: true,
user: buildUserResponse(updatedResult.rows[0]),
});
} catch (err) {
if (transactionStarted) {
try {
await client.query("ROLLBACK");
} catch (_) {}
}
console.error("POST /account/confirm-email-change error:", err);
if (err && err.code === "23505") {
return res.status(409).json({
ok: false,
error: "That email is already associated with another account.",
});
}
return res.status(500).json({ ok: false, error: "Server error" });
} finally {
client.release();
}
});
// -------------------------
// Cuenta: cambiar contraseña
// -------------------------
app.post("/account/change-password", authMiddleware, async (req, res) => {
try {
const { userId } = req;
const { currentPassword, newPassword } = req.body || {};
if (!currentPassword || !newPassword) {
return res.status(400).json({
ok: false,
error: "Contraseña actual y nueva contraseña son requeridas",
});
}
const { rows } = await pool.query(
"SELECT * FROM users WHERE id = $1 LIMIT 1",
[userId]
);
if (rows.length === 0) {
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const user = rows[0];
const match = await bcrypt.compare(currentPassword, user.password_hash);
if (!match) {
return res.status(401).json({ ok: false, error: "Contraseña actual incorrecta" });
}
const newHash = await bcrypt.hash(newPassword, 10);
const { rows: updatedRows } = await pool.query(
`
UPDATE users
SET password_hash = $1
WHERE id = $2
RETURNING *;
`,
[newHash, userId]
);
const updatedUser = buildUserResponse(updatedRows[0]);
return res.json({
ok: true,
user: updatedUser,
});
} catch (err) {
console.error("POST /account/change-password error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// ADMIN: login
// -------------------------
app.post("/admin/login", async (req, res) => {
try {
const { email, password } = req.body || {};
if (!email || !password) {
return res
.status(400)
.json({ ok: false, error: "Email y contraseña son requeridos" });
}
const normalizedEmail = String(email).trim().toLowerCase();
const { rows } = await pool.query(
"SELECT * FROM users WHERE email = $1 LIMIT 1",
[normalizedEmail]
);
if (rows.length === 0) {
return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
}
const user = rows[0];
if (!user.is_admin) {
return res
.status(403)
.json({ ok: false, error: "No tienes permisos de administrador" });
}
const passwordMatch = await bcrypt.compare(password, user.password_hash);
if (!passwordMatch) {
return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
}
const token = createToken(user);
const adminUser = {
id: user.id,
full_name: user.full_name,
email: user.email,
refid: user.refid,
is_admin: !!user.is_admin,
};
return res.json({
ok: true,
token,
admin: adminUser,
});
} catch (err) {
console.error("POST /admin/login error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// ADMIN: stats
// -------------------------
app.get("/admin/stats", adminAuthMiddleware, async (req, res) => {
try {
const statsQuery = `
SELECT
COUNT(*)::int AS total_users,
COALESCE(SUM(referrals), 0)::int AS total_referrals,
COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')::int AS users_last_7_days
FROM users;
`;
const topReferrersQuery = `
SELECT
id,
full_name,
email,
refid,
COALESCE(referrals, 0)::int AS referrals
FROM users
WHERE referrals IS NOT NULL AND referrals > 0
ORDER BY referrals DESC
LIMIT 10;
`;
const [statsResult, topResult] = await Promise.all([
pool.query(statsQuery),
pool.query(topReferrersQuery),
]);
const stats = statsResult.rows[0];
return res.json({
ok: true,
stats,
topReferrers: topResult.rows,
});
} catch (err) {
console.error("GET /admin/stats error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// ADMIN: referral stats reales
// -------------------------
app.get("/admin/referral-stats", adminAuthMiddleware, async (req, res) => {
  try {
    const statsResult = await pool.query(`
      SELECT
        COUNT(*)::int AS total_referrals,

        COUNT(*) FILTER (
          WHERE referral_status = 'pending'
        )::int AS pending_referrals,

        COUNT(*) FILTER (
          WHERE referral_status = 'qualified'
        )::int AS qualified_referrals

      FROM stripe_checkout_access

      WHERE payment_status = 'paid'
        AND ref_code IS NOT NULL
        AND TRIM(ref_code) <> '';
    `);

    const topResult = await pool.query(`
      SELECT
        u.id,
        u.full_name,
        u.email,
        u.refid,
        COUNT(*)::int AS qualified_referrals

      FROM stripe_checkout_access s

      JOIN users u
        ON UPPER(u.refid) = UPPER(s.ref_code)

      WHERE s.payment_status = 'paid'
        AND s.signup_used = TRUE
        AND s.user_id IS NOT NULL
        AND s.referral_status = 'qualified'
        AND s.ref_code IS NOT NULL
        AND TRIM(s.ref_code) <> ''

      GROUP BY
        u.id,
        u.full_name,
        u.email,
        u.refid

      ORDER BY qualified_referrals DESC
      LIMIT 10;
    `);

    return res.json({
      ok: true,
      stats: statsResult.rows[0],
      topReferrers: topResult.rows,
    });
  } catch (err) {
    console.error("GET /admin/referral-stats error:", err);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});
// -------------------------
// ADMIN: transferencia de recompensa Live de prueba
// -------------------------
app.post(
  "/admin/test-referral-transfer",
  adminAuthMiddleware,
  async (req, res) => {
    try {
      const testRewardCents = Number(
        process.env.TMKP_LIVE_TEST_REWARD_CENTS || 0
      );

      if (
        !Number.isInteger(testRewardCents) ||
        testRewardCents <= 0
      ) {
        return res.status(503).json({
          ok: false,
          error: "Live test reward is not configured.",
        });
      }
if (req.body?.confirm !== "SEND_LIVE_TEST_REWARD") {
  return res.status(400).json({
    ok: false,
    code: "CONFIRMATION_REQUIRED",
    error: "Explicit confirmation is required.",
  });
}
     const referralCheckoutId = Number(
  req.body?.referralCheckoutId
);

if (
  !Number.isInteger(referralCheckoutId) ||
  referralCheckoutId <= 0
) {
  return res.status(400).json({
    ok: false,
    code: "INVALID_REFERRAL",
    error: "A valid referral checkout ID is required.",
  });
}
     const { rows } = await pool.query(
  `
  SELECT
    r.id AS reward_id,
    r.referral_checkout_id,
    r.sponsor_user_id,
    r.amount_cents,
    r.currency,
    r.status AS reward_status,
    c.referral_status,
    u.stripe_connect_account_id
  FROM referral_rewards r
  JOIN stripe_checkout_access c
    ON c.id = r.referral_checkout_id
  JOIN users u
    ON u.id = r.sponsor_user_id
  WHERE r.referral_checkout_id = $1
    AND r.amount_cents = $2
    AND r.status = 'pending'
AND c.referral_status = 'qualified'
  LIMIT 1;
  `,
  [referralCheckoutId, testRewardCents]
);

if (rows.length === 0) {
  return res.status(404).json({
    ok: false,
    code: "TEST_REWARD_NOT_READY",
    error: "The test reward is not ready yet.",
  });
}
     const reward = rows[0];

const accountId = String(
  reward.stripe_connect_account_id || ""
).trim();

if (!accountId) {
  return res.status(409).json({
    ok: false,
    code: "CONNECT_NOT_CONFIGURED",
    error: "Sponsor has not configured Stripe Connect.",
  });
}
     if (!stripe) {
  return res.status(503).json({
    ok: false,
    error: "Stripe is not configured.",
  });
}

const account = await stripe.accounts.retrieve(accountId);

if (
  account.details_submitted !== true ||
  account.payouts_enabled !== true ||
  account.capabilities?.transfers !== "active"
) {
  return res.status(409).json({
    ok: false,
    code: "CONNECT_NOT_READY",
    error: "Sponsor Stripe Connect account is not ready.",
  });
}
    const transfer = await stripe.transfers.create(
  {
    amount: reward.amount_cents,
    currency: reward.currency,
    destination: accountId,
    metadata: {
      tmkp_reward_id: String(reward.reward_id),
      referral_checkout_id: String(reward.referral_checkout_id),
      purpose: "admin_live_test_referral_reward",
    },
  },
  {
    idempotencyKey: `tmkp-admin-live-test-reward-${reward.reward_id}`,
  }
);

await pool.query(
  `
  UPDATE referral_rewards
  SET status = 'transferred',
      stripe_transfer_id = $2,
      transferred_at = NOW(),
      updated_at = NOW()
  WHERE id = $1
    AND status = 'pending';
  `,
  [reward.reward_id, transfer.id]
);

return res.json({
  ok: true,
  transferred: true,
  rewardId: reward.reward_id,
  referralCheckoutId: reward.referral_checkout_id,
  amountCents: reward.amount_cents,
  currency: reward.currency,
  transferId: transfer.id,
});
    } catch (err) {
  console.error(
    "POST /admin/test-referral-transfer error:",
    err
  ); 
      return res.status(500).json({
        ok: false,
        error: "Could not process admin test transfer.",
      });
    }
  }
);
// -------------------------
// ADMIN: pagos pendientes de activación
// -------------------------
app.get("/admin/pending-activations", adminAuthMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        id,
        full_name,
        email,
        phone,
        country,
        ref_code,
        lang,
        amount_total,
        currency,
        paid_at,
        continuation_email_sent_at,
        referral_status,
        referral_review_after,
        created_at
      FROM stripe_checkout_access
      WHERE payment_status = 'paid'
        AND signup_used = FALSE
      ORDER BY COALESCE(paid_at, created_at) DESC;
    `);

    return res.json({
      ok: true,
      pendingActivations: rows,
    });
  } catch (err) {
    console.error("GET /admin/pending-activations error:", err);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});
// -------------------------
// ADMIN: lista de usuarios con búsqueda y paginación
// -------------------------
app.get("/admin/users", adminAuthMiddleware, async (req, res) => {
try {
const search = (req.query.search || "").trim();
const page = parseInt(req.query.page, 10) || 1;
const pageSize = Math.min(parseInt(req.query.pageSize, 10) || 20, 100);
const offset = (page - 1) * pageSize;
const params = [];
let whereClause = "";
if (search) {
params.push(`%${search.toLowerCase()}%`);
whereClause = `
WHERE
LOWER(full_name) LIKE $1
OR LOWER(email) LIKE $1
OR LOWER(refid) LIKE $1
`;
}
const countQuery = `
SELECT COUNT(*)::int AS total
FROM users
${whereClause};
`;
const listQuery = `
SELECT
id,
full_name,
email,
phone,
refid,
referredby,
 COALESCE(
  (
    SELECT p.current_unit
    FROM user_content_progress p
    WHERE p.user_id = users.id
      AND p.content_key = 'ebook_abundance'
    LIMIT 1
  ),
  0
)::int AS ebook_current_unit,

COALESCE(
  (
    SELECT p.status
    FROM user_content_progress p
    WHERE p.user_id = users.id
      AND p.content_key = 'ebook_abundance'
    LIMIT 1
  ),
  'not_started'
) AS ebook_status,

 COALESCE(
  (
    SELECT p.current_unit
    FROM user_content_progress p
    WHERE p.user_id = users.id
      AND p.content_key = 'truth_path'
    LIMIT 1
  ),
  0
)::int AS ttp_current_unit,

COALESCE(
  (
    SELECT p.status
    FROM user_content_progress p
    WHERE p.user_id = users.id
      AND p.content_key = 'truth_path'
    LIMIT 1
  ),
  'locked'
) AS ttp_status,
 (
  SELECT COUNT(*)::int
  FROM stripe_checkout_access s
  WHERE UPPER(s.ref_code) = UPPER(users.refid)
    AND s.payment_status = 'paid'
    AND s.signup_used = TRUE
    AND s.user_id IS NOT NULL
    AND s.referral_status = 'qualified'
) AS referrals,
is_admin,
created_at,
lang,
country
FROM users
${whereClause}
ORDER BY created_at DESC
LIMIT $${params.length + 1}
OFFSET $${params.length + 2};
`;
const countParams = [...params];
const listParams = [...params, pageSize, offset];
const [countResult, listResult] = await Promise.all([
pool.query(countQuery, countParams),
pool.query(listQuery, listParams),
]);
const total = countResult.rows[0].total;
const users = listResult.rows;
return res.json({
ok: true,
page,
pageSize,
total,
totalPages: Math.ceil(total / pageSize),
users,
});
} catch (err) {
console.error("GET /admin/users error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// Inicio del servidor
// -------------------------
const TMK_PHASES = [
{ phase: 1, limitPerHour: 4, price: 497, reward: 177.30, maxPayments: 7 },
{ phase: 2, limitPerHour: 2, price: 777, reward: 177.30, maxPayments: 2 },
{ phase: 3, limitPerHour: 2, price: 1270, reward: 250.00, maxPayments: 2 },
{ phase: 4, limitPerHour: 2, price: 1970, reward: 447.00, maxPayments: null },
];
// Calcula la fase actual por total de pagos
async function getCurrentPhase() {
const { rows } = await pool.query(`SELECT COUNT(*)::int AS total FROM payments;`);
const total = rows[0]?.total || 0;
let current = TMK_PHASES[TMK_PHASES.length - 1];
for (const p of TMK_PHASES) {
if (p.maxPayments && total < p.maxPayments) { current = p; break; }
}
return { totalPayments: total, config: current };
}
app.get("/gate/status", async (req, res) => {
try {
const { config, totalPayments } = await getCurrentPhase();
// pagos en los últimos 60 minutos
const { rows } = await pool.query(`
SELECT COUNT(*)::int AS last_hour
FROM payments
WHERE created_at >= NOW() - INTERVAL '60 minutes';
`);
const lastHour = rows[0]?.last_hour || 0;
const isOpen = lastHour < config.limitPerHour;
// Para countdown simple: si está cerrado, estimamos “retry” a 60 min desde el pago más viejo dentro de la hora
let retrySeconds = 0;
if (!isOpen) {
const oldest = await pool.query(`
SELECT created_at
FROM payments
WHERE created_at >= NOW() - INTERVAL '60 minutes'
ORDER BY created_at ASC
LIMIT 1;
`);
const oldestTs = oldest.rows[0]?.created_at;
if (oldestTs) {
// segundos hasta que ese pago salga de la ventana de 60 min
const diff = await pool.query(`SELECT EXTRACT(EPOCH FROM (($1::timestamptz + INTERVAL '60 minutes') - NOW()))::int AS s;`, [oldestTs]);
retrySeconds = Math.max(diff.rows[0]?.s || 0, 0);
} else {
retrySeconds = 60 * 60;
}
}
return res.json({
ok: true,
gate: {
open: isOpen,
lastHour,
limitPerHour: config.limitPerHour,
retrySeconds,
},
phase: {
phase: config.phase,
price: config.price,
reward: config.reward,
totalPayments,
},
});
} catch (err) {
console.error("GET /gate/status error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
app.post("/dev/mock-payment", adminAuthMiddleware, async (req, res) => {
try {
const amount = Number(req.body?.amount || 0);
const amountCents = Math.round(amount * 100);
if (!amountCents || amountCents < 100) {
return res.status(400).json({ ok: false, error: "amount inválido" });
}
const { config } = await getCurrentPhase();
const { rows } = await pool.query(
`INSERT INTO payments (amount_cents, currency, phase) VALUES ($1,'usd',$2) RETURNING *;`,
[amountCents, config.phase]
);
return res.json({ ok: true, payment: rows[0] });
} catch (err) {
console.error("POST /dev/mock-payment error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
}
});
// -------------------------
// AUTH: Forgot Password
// -------------------------
app.post("/auth/forgot-password", async (req, res) => {
try {
const { email } = req.body || {};
if (!email) {
return res.status(400).json({
ok: false,
error: "Email is required",
});
}
const normalizedEmail = String(email).trim().toLowerCase();
const { rows } = await pool.query(
"SELECT * FROM users WHERE email = $1 LIMIT 1",
[normalizedEmail]
);
// Por seguridad, siempre respondemos ok:true
if (rows.length === 0) {
return res.json({ ok: true });
}
const user = rows[0];
const resetToken = crypto.randomBytes(32).toString("hex");
const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
await pool.query(
`
UPDATE users
SET reset_token = $1,
reset_token_expires = $2
WHERE id = $3
`,
[resetToken, expiresAt, user.id]
);
const resetUrl =
`https://themasterkeyprogram.com/reset-password.html?token=${resetToken}`;
const lang = (user.lang === "en") ? "en" : "es";
const subject =
lang === "en"
? "Reset your password"
: "Restablece tu contraseña";
const html =
lang === "en"
? `
<h2>The Master Key</h2>
<p>Click the button below to reset your password.</p>
<p>
<a href="${resetUrl}&lang=en"
style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:999px;">
Reset Password
</a>
</p>
<p>This link expires in 1 hour.</p>
`
: `
<h2>The Master Key</h2>
<p>Haz clic en el botón para restablecer tu contraseña.</p>
<p>
<a href="${resetUrl}&lang=es"
style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:999px;">
Restablecer contraseña
</a>
</p>
<p>Este enlace expira en 1 hora.</p>
`;
await resend.emails.send({
from: "The Master Key <support@themasterkeyprogram.com>",
to: user.email,
subject,
html,
});
return res.json({ ok: true });
} catch (err) {
console.error("POST /auth/forgot-password error:", err);
return res.status(500).json({
ok: false,
error: "Server error",
});
}
});
// -------------------------
// AUTH: Reset Password
// -------------------------
app.post("/auth/reset-password", async (req, res) => {
try {
const { token, password } = req.body || {};
if (!token || !password) {
return res.status(400).json({
ok: false,
error: "Token and password are required",
});
}
const { rows } = await pool.query(
`
SELECT *
FROM users
WHERE reset_token = $1
AND reset_token_expires > NOW()
LIMIT 1
`,
[token]
);
if (rows.length === 0) {
return res.status(400).json({
ok: false,
error: "Invalid or expired token",
});
}
const user = rows[0];
const passwordHash = await bcrypt.hash(password, 10);
await pool.query(
`
UPDATE users
SET password_hash = $1,
reset_token = NULL,
reset_token_expires = NULL
WHERE id = $2
`,
[passwordHash, user.id]
);
return res.json({ ok: true });
} catch (err) {
console.error("POST /auth/reset-password error:", err);
return res.status(500).json({
ok: false,
error: "Server error",
});
}
});
app.listen(PORT, () => {
console.log(`[OK] Mente Abundante API escuchando en el puerto ${PORT}`);
});
