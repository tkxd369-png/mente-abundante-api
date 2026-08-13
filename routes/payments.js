 const express = require("express");
const Stripe = require("stripe");
const { Pool } = require("pg");
const router = express.Router();
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
if (!STRIPE_SECRET_KEY) console.warn("[payments] STRIPE_SECRET_KEY is not configured.");
if (!DATABASE_URL) console.warn("[payments] DATABASE_URL is not configured.");
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
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
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_stripe_checkout_access_email
ON stripe_checkout_access (LOWER(email));
`);
await pool.query(`
CREATE INDEX IF NOT EXISTS idx_stripe_checkout_access_ref_code
ON stripe_checkout_access (ref_code);
`);
}
if (pool) {
ensurePaymentsTable().catch((err) => {
console.error("[payments] Could not initialize payments table:", err);
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
mode: STRIPE_SECRET_KEY.startsWith("sk_test_")
? "test"
: "live-or-unknown",
checkoutAmountCents: CHECKOUT_AMOUNT_CENTS,
});
});
router.post("/create-checkout", async (req, res) => {
try {
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
const session = await stripe.checkout.sessions.create({
mode: "payment",
// Force Stripe Checkout to match the TMKP language flow.
// Spanish uses Stripe's Latin American Spanish locale.
locale: lang === "en" ? "en" : "es-419",
customer_email: email,
line_items: [
{
price_data: {
currency: "usd",
unit_amount: CHECKOUT_AMOUNT_CENTS,
product_data: {
name: PRODUCT_NAME,
description: PRODUCT_DESCRIPTION,
},
},
quantity: 1,
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
success_url: `${signupUrl}?session_id={CHECKOUT_SESSION_ID}`,
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
sessionId: session.id,
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
switch (event.type) {
case "checkout.session.completed": {
const session = event.data.object;
await upsertCheckoutRecord(session);
break;
}
case "checkout.session.async_payment_succeeded": {
const session = event.data.object;
session.payment_status = "paid";
await upsertCheckoutRecord(session);
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
router.get("/verify-session", async (req, res) => {
try {
if (!pool) {
return res.status(503).json({ error: "Database is not configured." });
}
const sessionId = clean(req.query?.session_id, 255);
if (!sessionId || !sessionId.startsWith("cs_")) {
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
signup_used
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
