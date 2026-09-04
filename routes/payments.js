 const express = require("express");
const Stripe = require("stripe");
const crypto = require("crypto");
const { Pool } = require("pg");
const Resend = require("resend").Resend;
const router = express.Router();
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const TMKP_STRIPE_PRICE_ID = process.env.TMKP_STRIPE_PRICE_ID || "";
const STRIPE_LIVE_TEST_COUPON_ID = process.env.STRIPE_LIVE_TEST_COUPON_ID || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
if (!STRIPE_SECRET_KEY) console.warn("[payments] STRIPE_SECRET_KEY is not configured.");
if (!DATABASE_URL) console.warn("[payments] DATABASE_URL is not configured.");
if (!RESEND_API_KEY) console.warn("[payments] RESEND_API_KEY is not configured; payment continuation emails will be skipped.");
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const pool = DATABASE_URL
? new Pool({
connectionString: DATABASE_URL,
ssl: process.env.NODE_ENV === "production"
? { rejectUnauthorized: false }
: undefined,
})
: null;
const CHECKOUT_AMOUNT_CENTS = Number(
process.env.TMKP_CHECKOUT_AMOUNT_CENTS || "49500"
);
const SITE_URL = (
process.env.TMKP_SITE_URL || "https://themasterkeyprogram.com"
).replace(/\/+$/, "");
const PRODUCT_NAME = "The Master Key Program - Lifetime Membership";
const PRODUCT_DESCRIPTION =
"Lifetime access to The Master Key Program, including educational content, digital resources, and member tools.";
async function ensurePaymentsTable() {
if (!pool) return;
await pool.query(`
CREATE TABLE IF NOT EXISTS stripe_checkout_access (
id BIGSERIAL PRIMARY KEY,
stripe_session_id TEXT UNIQUE NOT NULL,
stripe_payment_intent TEXT,
user_id BIGINT,
email TEXT NOT NULL,
full_name TEXT,
phone TEXT,
country TEXT,
ref_code TEXT,
lang TEXT NOT NULL DEFAULT 'es',
amount_total INTEGER,
currency TEXT DEFAULT 'usd',
payment_status TEXT NOT NULL DEFAULT 'pending',
paid_at TIMESTAMPTZ,
signup_used BOOLEAN NOT NULL DEFAULT FALSE,
signup_used_at TIMESTAMPTZ,
continuation_email_sent_at TIMESTAMPTZ,
continuation_token_hash TEXT,
referral_status TEXT NOT NULL DEFAULT 'none',
referral_review_after TIMESTAMPTZ,
referral_approved_at TIMESTAMPTZ,
referral_approval_email_sent_at TIMESTAMPTZ,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
await pool.query(`
ALTER TABLE stripe_checkout_access
ADD COLUMN IF NOT EXISTS user_id BIGINT;
`);
await pool.query(`
ALTER TABLE stripe_checkout_access
ADD COLUMN IF NOT EXISTS continuation_email_sent_at TIMESTAMPTZ;
`);
 await pool.query(`
ALTER TABLE stripe_checkout_access
ADD COLUMN IF NOT EXISTS continuation_token_hash TEXT;
`);
 await pool.query(`
ALTER TABLE stripe_checkout_access
ADD COLUMN IF NOT EXISTS referral_status TEXT NOT NULL DEFAULT 'none',
ADD COLUMN IF NOT EXISTS referral_review_after TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS referral_approved_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS referral_approval_email_sent_at TIMESTAMPTZ;
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_stripe_checkout_access_user_id
ON stripe_checkout_access (user_id);
`);
// Permanent account-email aliases. The server also ensures this table;
// defining it here keeps duplicate-charge protection self-contained.
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
// Reserve current account emails and backfill old consumed purchases.
await pool.query(`
INSERT INTO account_email_history (user_id, email)
SELECT id, LOWER(email)
FROM users
WHERE email IS NOT NULL AND TRIM(email) <> ''
ON CONFLICT DO NOTHING;
`).catch(() => {});
await pool.query(`
UPDATE stripe_checkout_access AS sca
SET user_id = u.id,
updated_at = NOW()
FROM users AS u
WHERE sca.user_id IS NULL
AND sca.signup_used = TRUE
AND LOWER(sca.email) = LOWER(u.email);
`).catch(() => {});
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_stripe_checkout_access_email
ON stripe_checkout_access (LOWER(email));
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_stripe_checkout_access_ref_code
ON stripe_checkout_access (ref_code);
`);
}
let paymentsReady = Promise.resolve();
if (pool) {
paymentsReady = ensurePaymentsTable().catch((err) => {
console.error("[payments] Could not initialize payments table:", err);
throw err;
});
}
function clean(value, max = 250) {
return String(value || "").trim().slice(0, max);
}
function normalizeEmail(value) {
return clean(value, 320).toLowerCase();
}
function normalizeLang(value) {
return clean(value, 5).toLowerCase() === "en" ? "en" : "es";
}
function addBusinessDays(startDate, businessDays) {
const result = new Date(startDate);
let remaining = Number(businessDays) || 0;

while (remaining > 0) {
result.setUTCDate(result.getUTCDate() + 1);

const day = result.getUTCDay();

if (day !== 0 && day !== 6) {
remaining -= 1;
}
}

return result;
}
function getSignupUrl(lang) {
return lang === "en"
? `${SITE_URL}/signup-en.html`
: `${SITE_URL}/signup.html`;
}
function getMembershipUrl(lang, refCode) {
const page = lang === "en" ? "membresia-en.html" : "membresia.html";
const base = `${SITE_URL}/${page}`;
return refCode ? `${base}?ref=${encodeURIComponent(refCode)}` : base;
}
function escapeHtml(value) {
return String(value || "")
.replace(/&/g, "&amp;")
.replace(/</g, "&lt;")
.replace(/>/g, "&gt;")
.replace(/"/g, "&quot;")
.replace(/'/g, "&#039;");
}
function hashContinuationToken(token) {
  return crypto
    .createHash("sha256")
    .update(String(token || ""))
    .digest("hex");
}
async function sendPaymentContinuationEmailIfNeeded(sessionId, forceResend = false) { 
if (!pool) throw new Error("Database is not configured.");
if (!resend) {
console.warn(
`[payments/email] RESEND_API_KEY is not configured; continuation email skipped for ${sessionId}.`
);
return;
}
const { rows } = await pool.query(
`
SELECT
stripe_session_id,
email,
full_name,
lang,
 payment_status,
signup_used,
continuation_email_sent_at
FROM stripe_checkout_access
WHERE stripe_session_id = $1
LIMIT 1;
`,
[sessionId]
);
if (!rows.length) return;
const row = rows[0];
if (row.payment_status !== "paid") return;
if (row.signup_used) return;
if (row.continuation_email_sent_at && !forceResend) return; 
const lang = normalizeLang(row.lang);
 const continuationToken = crypto.randomBytes(32).toString("hex");
const continuationTokenHash = hashContinuationToken(continuationToken);
 const signupUrl =
  `${getSignupUrl(lang)}?session_id=${encodeURIComponent(sessionId)}` +
  `&token=${encodeURIComponent(continuationToken)}`;
const safeName = escapeHtml(row.full_name || "");
const firstName = safeName ? safeName.split(/\s+/)[0] : "";
const subject =
lang === "en"
? "Payment confirmed — continue your TMKP registration"
: "Pago confirmado — continúa tu registro de TMKP";
const html =
lang === "en"
? `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6;max-width:620px;margin:0 auto;">
<h2 style="margin-bottom:8px;">The Master Key Program</h2>
<p>${firstName ? `Hi ${firstName},` : "Hello,"}</p>
<p>Your payment has been confirmed and your access is reserved.</p>
<p>Complete your registration to create your account and continue into The Master Key Program.</p>
<p style="margin:28px 0;">
<a href="${signupUrl}" style="display:inline-block;padding:13px 24px;background:#d4af37;color:#111;text-decoration:none;border-radius:999px;font-weight:700;">Continue my registration</a>
</p>
<p style="font-size:14px;color:#666;">This link is tied to your confirmed payment and can only be used to create one account.</p>
<p style="font-size:14px;color:#666;">If you already completed your registration, you can ignore this email.</p>
<p style="margin-top:28px;">The Master Key Program</p>
</div>
`
: `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.6;max-width:620px;margin:0 auto;">
<h2 style="margin-bottom:8px;">The Master Key Program</h2>
<p>${firstName ? `Hola ${firstName},` : "Hola,"}</p>
<p>Tu pago ha sido confirmado y tu acceso está reservado.</p>
<p>Completa tu registro para crear tu cuenta y continuar dentro de The Master Key Program.</p>
<p style="margin:28px 0;">
<a href="${signupUrl}" style="display:inline-block;padding:13px 24px;background:#d4af37;color:#111;text-decoration:none;border-radius:999px;font-weight:700;">Continuar mi registro</a>
</p>
<p style="font-size:14px;color:#666;">Este enlace está asociado a tu pago confirmado y solo puede utilizarse para crear una cuenta.</p>
<p style="font-size:14px;color:#666;">Si ya completaste tu registro, puedes ignorar este correo.</p>
<p style="margin-top:28px;">The Master Key Program</p>
</div>
`;
const text =
lang === "en"
? `${firstName ? `Hi ${firstName},\n\n` : "Hello,\n\n"}Your payment has been confirmed and your access is reserved.\n\nComplete your registration here:\n${signupUrl}\n\nThis link is tied to your confirmed payment and can only be used to create one account.\n\nThe Master Key Program`
: `${firstName ? `Hola ${firstName},\n\n` : "Hola,\n\n"}Tu pago ha sido confirmado y tu acceso está reservado.\n\nCompleta tu registro aquí:\n${signupUrl}\n\nEste enlace está asociado a tu pago confirmado y solo puede utilizarse para crear una cuenta.\n\nThe Master Key Program`;
const emailResult = await resend.emails.send(
{
from: "The Master Key <support@themasterkeyprogram.com>",
to: row.email,
subject,
html,
text,
},
 {
  idempotencyKey: forceResend
    ? `tmkp-payment-continuation/${sessionId}/resend-${Date.now()}`
    : `tmkp-payment-continuation/${sessionId}/initial`,
}
);
if (emailResult && emailResult.error) {
const message =
emailResult.error.message || JSON.stringify(emailResult.error);
throw new Error(`Resend continuation email failed: ${message}`);
}
await pool.query(
`
UPDATE stripe_checkout_access
SET continuation_email_sent_at = CASE
  WHEN $2::boolean = TRUE THEN NOW()
  ELSE COALESCE(continuation_email_sent_at, NOW())
END,
continuation_token_hash = $3,
updated_at = NOW() 
WHERE stripe_session_id = $1;
`, 
 [sessionId, forceResend, continuationTokenHash]
);
console.log(`[payments/email] Continuation email sent for ${sessionId}.`);
}
async function upsertCheckoutRecord(session, fallback = {}) {
if (!pool) throw new Error("Database is not configured.");
const metadata = session.metadata || {};
const email = normalizeEmail(
session.customer_details?.email ||
session.customer_email ||
metadata.email ||
fallback.email
);
if (!email) throw new Error("Checkout Session does not contain an email.");
const fullName = clean(
session.customer_details?.name ||
metadata.fullName ||
fallback.fullName,
180
);
const phone = clean(metadata.phone || fallback.phone, 60);
const country = clean(metadata.country || fallback.country, 8).toUpperCase();
const refCode = clean(metadata.refCode || fallback.refCode, 80).toUpperCase();
const lang = normalizeLang(metadata.lang || fallback.lang);
const status =
session.payment_status === "paid"
? "paid"
: clean(
session.payment_status ||
fallback.paymentStatus ||
"pending",
40
);
await pool.query(
`
INSERT INTO stripe_checkout_access (
stripe_session_id,
stripe_payment_intent,
email,
full_name,
phone,
country,
ref_code,
lang,
amount_total,
currency,
payment_status,
paid_at,
updated_at
)
VALUES (
$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
CASE WHEN $11 = 'paid' THEN NOW() ELSE NULL END,
NOW()
)
ON CONFLICT (stripe_session_id)
DO UPDATE SET
stripe_payment_intent = COALESCE(
EXCLUDED.stripe_payment_intent,
stripe_checkout_access.stripe_payment_intent
),
email = EXCLUDED.email,
full_name = COALESCE(
NULLIF(EXCLUDED.full_name, ''),
stripe_checkout_access.full_name
),
phone = COALESCE(
NULLIF(EXCLUDED.phone, ''),
stripe_checkout_access.phone
),
country = COALESCE(
NULLIF(EXCLUDED.country, ''),
stripe_checkout_access.country
),
ref_code = COALESCE(
NULLIF(EXCLUDED.ref_code, ''),
stripe_checkout_access.ref_code
),
lang = EXCLUDED.lang,
amount_total = COALESCE(
EXCLUDED.amount_total,
stripe_checkout_access.amount_total
),
currency = COALESCE(
EXCLUDED.currency,
stripe_checkout_access.currency
),
payment_status = EXCLUDED.payment_status,
paid_at = CASE
WHEN EXCLUDED.payment_status = 'paid'
THEN COALESCE(stripe_checkout_access.paid_at, NOW())
ELSE stripe_checkout_access.paid_at
END,
updated_at = NOW()
`,
[
session.id,
typeof session.payment_intent === "string"
? session.payment_intent
: null,
email,
fullName,
phone,
country,
refCode,
lang,
Number.isInteger(session.amount_total)
? session.amount_total
: CHECKOUT_AMOUNT_CENTS,
clean(session.currency || "usd", 10).toLowerCase(),
status,
]
);
if (refCode && status === "paid") {
const referralReviewAfter = addBusinessDays(new Date(), 5);

await pool.query(
`
UPDATE stripe_checkout_access
SET referral_status = CASE
WHEN referral_status = 'none' THEN 'pending'
ELSE referral_status
END,
referral_review_after = COALESCE(referral_review_after, $2),
updated_at = NOW()
WHERE stripe_session_id = $1
AND referral_status IN ('none', 'pending');
`,
[session.id, referralReviewAfter]
);
} 
}
async function setCheckoutStatus(sessionId, status) {
if (!pool) return;
await pool.query(
`
UPDATE stripe_checkout_access
SET payment_status = $2,
updated_at = NOW()
WHERE stripe_session_id = $1
`,
[sessionId, status]
);
}
router.get("/status", (req, res) => {
res.json({
ok: true,
module: "payments",
stripeConfigured: !!stripe,
webhookConfigured: !!STRIPE_WEBHOOK_SECRET,
databaseConfigured: !!pool,
emailConfigured: !!resend,
mode: STRIPE_SECRET_KEY.startsWith("sk_test_")
? "test"
: "live-or-unknown",
checkoutAmountCents: CHECKOUT_AMOUNT_CENTS,
});
});
router.post("/create-checkout", async (req, res) => {
try {
await paymentsReady;
if (!stripe) {
return res.status(503).json({ error: "Stripe is not configured." });
}
if (!pool) {
return res.status(503).json({ error: "Database is not configured." });
}
const fullName = clean(req.body?.fullName, 180);
const email = normalizeEmail(req.body?.email);
const phone = clean(req.body?.phone, 60);
const country = clean(req.body?.country, 8).toUpperCase();
const refCode = clean(req.body?.refCode, 80).toUpperCase();
const lang = normalizeLang(req.body?.lang);
if (!fullName || !email || !phone || !country || !refCode) {
return res.status(400).json({
error:
"Missing required checkout information: fullName, email, phone, country, or refCode.",
});
}
const signupUrl = getSignupUrl(lang);
const cancelUrl = getMembershipUrl(lang, refCode);
// PREVENT DUPLICATE CHARGES:
// 1) If this email already owns an account, do not open Stripe again.
const existingUser = await pool.query(
`
SELECT id, email
FROM users
WHERE LOWER(email) = LOWER($1)
UNION ALL
SELECT u.id, u.email
FROM account_email_history AS h
JOIN users AS u ON u.id = h.user_id
WHERE LOWER(h.email) = LOWER($1)
LIMIT 1
`,
[email]
);
if (existingUser.rows.length > 0) {
return res.status(409).json({
ok: false,
code: "ACCOUNT_EXISTS",
error:
lang === "en"
? "An account already exists for this email."
: "Ya existe una cuenta con este correo.",
redirectUrl:
lang === "en"
? `${SITE_URL}/login.html?lang=en`
: `${SITE_URL}/login.html`,
});
}
// 2) If this email already has a confirmed payment that has not yet
// been used to create an account, resume that signup instead of
// collecting a second payment.
const existingPaidCheckout = await pool.query(
`
SELECT stripe_session_id
FROM stripe_checkout_access
WHERE LOWER(email) = LOWER($1)
AND payment_status = 'paid'
AND signup_used = FALSE
ORDER BY updated_at DESC
LIMIT 1
`,
[email]
);
if (existingPaidCheckout.rows.length > 0) {
const existingSessionId =
existingPaidCheckout.rows[0].stripe_session_id;
return res.status(409).json({
ok: false,
code: "PAYMENT_ALREADY_CONFIRMED",
error:
lang === "en"
? "A confirmed payment already exists for this email."
: "Ya existe un pago confirmado para este correo.",
redirectUrl:
  `${SITE_URL}/payment-confirmed.html?lang=${lang}`, 
});
}
const session = await stripe.checkout.sessions.create({
mode: "payment",
// Force Stripe Checkout to match the TMKP language flow.
// Spanish uses Stripe's Latin American Spanish locale.
locale: lang === "en" ? "en" : "es-419",
customer_email: email,
line_items: [
{
price: TMKP_STRIPE_PRICE_ID,
quantity: 1,
},
], 
// TEMPORARY: Live $7 test coupon
discounts: [
{
coupon: STRIPE_LIVE_TEST_COUPON_ID,
},
], 
metadata: {
fullName,
email,
phone,
country,
refCode,
lang,
source: "tmkp_membership",
},
payment_intent_data: {
metadata: {
email,
refCode,
lang,
source: "tmkp_membership",
},
},
success_url: `${SITE_URL}/payment-confirmed.html?lang=${lang}`, 
cancel_url: cancelUrl,
});
await upsertCheckoutRecord(session, {
fullName,
email,
phone,
country,
refCode,
lang,
paymentStatus: "pending",
});
return res.json({
ok: true,
checkoutUrl: session.url,
 
});
} catch (err) {
console.error("[payments/create-checkout]", err);
return res.status(500).json({
error: "Could not create Stripe Checkout Session.",
});
}
});
router.post("/webhook", async (req, res) => {
if (!stripe) {
return res.status(503).send("Stripe is not configured.");
}
if (!STRIPE_WEBHOOK_SECRET) {
return res.status(503).send("Stripe webhook secret is not configured.");
}
const signature = req.headers["stripe-signature"];
const payload = Buffer.isBuffer(req.rawBody)
? req.rawBody
: Buffer.isBuffer(req.body)
? req.body
: null;
if (!payload) {
return res.status(500).send(
"Webhook raw body is unavailable. Configure server.js to preserve req.rawBody."
);
}
let event;
try {
event = stripe.webhooks.constructEvent(
payload,
signature,
STRIPE_WEBHOOK_SECRET
);
} catch (err) {
console.error(
"[payments/webhook] Signature verification failed:",
err.message
);
return res.status(400).send(`Webhook Error: ${err.message}`);
}
try {
await paymentsReady;
switch (event.type) {
case "checkout.session.completed": {
const session = event.data.object;
await upsertCheckoutRecord(session);
await sendPaymentContinuationEmailIfNeeded(session.id);
break;
}
case "checkout.session.async_payment_succeeded": {
const session = event.data.object;
session.payment_status = "paid";
await upsertCheckoutRecord(session);
await sendPaymentContinuationEmailIfNeeded(session.id);
break;
}
case "checkout.session.async_payment_failed": {
const session = event.data.object;
await setCheckoutStatus(session.id, "failed");
break;
}
case "checkout.session.expired": {
const session = event.data.object;
await setCheckoutStatus(session.id, "expired");
break;
}
default:
break;
}
return res.json({ received: true });
} catch (err) {
console.error("[payments/webhook] Handler error:", err);
return res.status(500).send("Webhook handler failed.");
}
});
router.post("/resend-continuation", async (req, res) => {
  try {
    await paymentsReady;

    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "Database is not configured.",
      });
    }

    if (!resend) {
      return res.status(503).json({
        ok: false,
        error: "Email service is not configured.",
      });
    }

    const sessionId = clean(req.body?.sessionId, 255);

    if (!sessionId || !sessionId.startsWith("cs_")) {
      return res.status(400).json({
        ok: false,
        error: "Invalid Checkout Session.",
      });
    }

    const { rows } = await pool.query(
      `
      SELECT
        stripe_session_id,
        lang,
        payment_status,
        signup_used,
        continuation_email_sent_at
      FROM stripe_checkout_access
      WHERE stripe_session_id = $1
      LIMIT 1;
      `,
      [sessionId]
    );

    if (!rows.length) {
      return res.status(404).json({
        ok: false,
        error: "Checkout Session was not found.",
      });
    }

    const row = rows[0];
    const lang = normalizeLang(row.lang);

    if (row.payment_status !== "paid") {
      return res.status(402).json({
        ok: false,
        error:
          lang === "en"
            ? "Payment has not been confirmed."
            : "El pago todavía no ha sido confirmado.",
      });
    }

    if (row.signup_used) {
      return res.status(409).json({
        ok: false,
        error:
          lang === "en"
            ? "This payment has already been used to create an account."
            : "Este pago ya fue utilizado para crear una cuenta.",
      });
    }

    if (row.continuation_email_sent_at) {
      const expiresAt =
        new Date(row.continuation_email_sent_at).getTime() +
        48 * 60 * 60 * 1000;

      if (Date.now() <= expiresAt) {
        return res.status(429).json({
          ok: false,
          code: "VERIFICATION_LINK_STILL_ACTIVE",
          error:
            lang === "en"
              ? "Your current verification link is still active."
              : "Tu enlace de verificación actual todavía está activo.",
        });
      }
    }

    await sendPaymentContinuationEmailIfNeeded(sessionId, true);

    return res.json({
      ok: true,
      sent: true,
      expiresInHours: 48,
    });
  } catch (err) {
    console.error("[payments/resend-continuation]", err);

    return res.status(500).json({
      ok: false,
      error: "Could not resend verification email.",
    });
  }
});
router.get("/verify-session", async (req, res) => {
try {
await paymentsReady;
if (!pool) {
return res.status(503).json({ error: "Database is not configured." });
}
const sessionId = clean(req.query?.session_id, 255);
const continuationToken = clean(req.query?.token, 128); 
 if (
  !sessionId ||
  !sessionId.startsWith("cs_") ||
  !continuationToken
) {
return res.status(400).json({
authorized: false,
error: "Invalid Checkout Session.",
});
}
const result = await pool.query(
`
SELECT
stripe_session_id,
email,
full_name,
phone,
country,
ref_code,
lang,
amount_total,
currency,
payment_status,
signup_used,
continuation_email_sent_at,
continuation_token_hash 
FROM stripe_checkout_access
WHERE stripe_session_id = $1
LIMIT 1
`,
[sessionId]
);
if (!result.rows.length) {
return res.status(404).json({
authorized: false,
error: "Checkout Session was not found.",
});
}
const row = result.rows[0];
const providedTokenHash = hashContinuationToken(continuationToken);
const storedTokenHash = String(row.continuation_token_hash || "");

const tokenMatches =
  /^[a-f0-9]{64}$/i.test(storedTokenHash) &&
  crypto.timingSafeEqual(
    Buffer.from(storedTokenHash, "hex"),
    Buffer.from(providedTokenHash, "hex")
  );

if (!tokenMatches) {
  return res.status(403).json({
    authorized: false,
    code: "INVALID_VERIFICATION_TOKEN",
    error: "This verification link is no longer valid.",
  });
} 
if (row.payment_status !== "paid") {
return res.status(402).json({
authorized: false,
error: "Payment has not been confirmed.",
});
}
if (row.signup_used) {
return res.status(409).json({
authorized: false,
error: "This payment has already been used to create an account.",
});
} 
if (!row.continuation_email_sent_at) {
  return res.status(403).json({
    authorized: false,
    code: "EMAIL_VERIFICATION_REQUIRED",
    error: "Email verification is required to continue.",
  });
}
 
const verificationExpiresAt =
  new Date(row.continuation_email_sent_at).getTime() +
  48 * 60 * 60 * 1000;

if (Date.now() > verificationExpiresAt) {
  return res.status(410).json({
    authorized: false,
    code: "VERIFICATION_LINK_EXPIRED",
    error:
      row.lang === "en"
        ? "This verification link has expired. Your payment remains confirmed."
        : "Este enlace de verificación ha expirado. Tu pago permanece confirmado.",
  });
} 

// Defense in depth:
// If an account already exists for the email tied to this paid Checkout
// Session, treat the payment as consumed even if signup_used was not
// previously flipped for any reason.
const existingUser = await pool.query(
`
SELECT id
FROM users
WHERE LOWER(email) = LOWER($1)
LIMIT 1
`,
[row.email]
);
if (existingUser.rows.length > 0) {
await pool.query(
`
UPDATE stripe_checkout_access
SET signup_used = TRUE,
signup_used_at = COALESCE(signup_used_at, NOW()),
updated_at = NOW()
WHERE stripe_session_id = $1
`,
[sessionId]
);
return res.status(409).json({
authorized: false,
error: "This payment has already been used to create an account.",
});
}
return res.json({
authorized: true,
sessionId: row.stripe_session_id,
fullName: row.full_name || "",
email: row.email || "",
phone: row.phone || "",
country: row.country || "",
refCode: row.ref_code || "",
lang: row.lang || "es",
amountTotal: row.amount_total,
currency: row.currency || "usd",
});
} catch (err) {
console.error("[payments/verify-session]", err);
return res.status(500).json({
authorized: false,
error: "Could not verify payment.",
});
}
});
router.post("/reactivate", (req, res) => {
res.status(501).json({
ok: false,
error: "Reactivation is not implemented.",
});
});
module.exports = router;
