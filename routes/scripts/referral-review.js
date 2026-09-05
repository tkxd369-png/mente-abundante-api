const Stripe = require("stripe");
const { Pool } = require("pg");
const { Resend } = require("resend");
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const SITE_URL = (process.env.TMKP_SITE_URL || "https://themasterkeyprogram.com").replace(/\/+$/, "");
const LIVE_TEST_REWARD_CENTS = Number(
  process.env.TMKP_LIVE_TEST_REWARD_CENTS || 0
);

const REFERRAL_REWARD_CENTS =
  Number.isInteger(LIVE_TEST_REWARD_CENTS) && LIVE_TEST_REWARD_CENTS > 0
    ? LIVE_TEST_REWARD_CENTS
    : 17820;
if (!STRIPE_SECRET_KEY) {
throw new Error("STRIPE_SECRET_KEY is not configured.");
}
if (!DATABASE_URL) {
throw new Error("DATABASE_URL is not configured.");
}
const stripe = new Stripe(STRIPE_SECRET_KEY);
const pool = new Pool({
connectionString: DATABASE_URL,
ssl:
process.env.NODE_ENV === "production"
? { rejectUnauthorized: false }
: undefined,
});
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
function clean(value, max = 250) {
return String(value || "").trim().slice(0, max);
}
function firstName(value) {
return clean(value, 180).split(/\s+/)[0] || "";
}
function escapeHtml(value) {
return String(value || "")
.replace(/&/g, "&amp;")
.replace(/</g, "&lt;")
.replace(/>/g, "&gt;")
.replace(/"/g, "&quot;")
.replace(/'/g, "&#039;");
}
async function getChargeForPaymentIntent(paymentIntent) {
if (!paymentIntent || !paymentIntent.latest_charge) return null;
if (typeof paymentIntent.latest_charge === "object") {
return paymentIntent.latest_charge;
}
return stripe.charges.retrieve(paymentIntent.latest_charge);
}
async function verifyStripePayment(row) {
let paymentIntentId = clean(row.stripe_payment_intent, 255);
if (!paymentIntentId) {
const session = await stripe.checkout.sessions.retrieve(row.stripe_session_id);
if (typeof session.payment_intent === "string") {
paymentIntentId = session.payment_intent;
} else if (session.payment_intent && session.payment_intent.id) {
paymentIntentId = session.payment_intent.id;
}
}
if (!paymentIntentId) {
return {
eligible: false,
reason: "missing_payment_intent",
};
}
const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId, {
expand: ["latest_charge"],
});
const charge = await getChargeForPaymentIntent(paymentIntent);
if (!charge) {
return {
eligible: false,
reason: "missing_charge",
};
}
if (paymentIntent.status !== "succeeded") {
return {
eligible: false,
reason: `payment_intent_${paymentIntent.status}`,
};
}
if (!charge.paid) {
return {
eligible: false,
reason: "charge_not_paid",
};
}
if (charge.captured === false) {
return {
eligible: false,
reason: "charge_not_captured",
};
}
if (charge.disputed) {
return {
eligible: false,
reason: "charge_disputed",
};
}
if (Number(charge.amount_refunded || 0) > 0) {
return {
eligible: false,
reason: "charge_refunded",
};
}
return {
eligible: true,
paymentIntentId,
chargeId: charge.id,
};
}
async function qualifyDueReferrals() {
const { rows } = await pool.query(`
SELECT
id,
stripe_session_id,
stripe_payment_intent,
user_id,
email,
ref_code,
lang,
paid_at,
referral_review_after
FROM stripe_checkout_access
WHERE payment_status = 'paid'
AND signup_used = TRUE
AND user_id IS NOT NULL
AND referral_status = 'pending'
AND referral_review_after IS NOT NULL
AND referral_review_after <= NOW()
AND ref_code IS NOT NULL
AND TRIM(ref_code) <> ''
ORDER BY referral_review_after ASC
LIMIT 100;
`);
console.log(`[referral-review] Due referrals: ${rows.length}`);
for (const row of rows) {
try {
const stripeCheck = await verifyStripePayment(row);
if (!stripeCheck.eligible) {
console.log(
`[referral-review] Keeping pending: ${row.stripe_session_id} (${stripeCheck.reason})`
);
continue;
}
 
const client = await pool.connect();

try {
  await client.query("BEGIN");

  const result = await client.query(
    `
    UPDATE stripe_checkout_access
    SET referral_status = 'qualified',
        referral_approved_at = COALESCE(referral_approved_at, NOW()),
        stripe_payment_intent = COALESCE(stripe_payment_intent, $2),
        updated_at = NOW()
    WHERE id = $1
      AND referral_status = 'pending'
    RETURNING id, stripe_session_id, ref_code;
    `,
    [row.id, stripeCheck.paymentIntentId]
  );

  if (result.rowCount === 1) {
    const rewardInsert = await client.query(
      `
      INSERT INTO referral_rewards (
        referral_checkout_id,
        sponsor_user_id,
        amount_cents,
        currency,
        status,
        qualified_at
      )
      SELECT
        $1,
        s.id,
        $2,
        'usd',
        'pending',
        NOW()
      FROM users s
      WHERE UPPER(s.refid) = UPPER($3)
      RETURNING id;
      `,
      [row.id, REFERRAL_REWARD_CENTS, row.ref_code]
    );

    if (rewardInsert.rowCount !== 1) {
      throw new Error(
        `Reward ledger entry could not be created for ${row.stripe_session_id}`
      );
    }

    await client.query("COMMIT");

    console.log(
      `[referral-review] QUALIFIED: ${row.stripe_session_id} -> ${row.ref_code}`
    );
  } else {
    await client.query("ROLLBACK");
  }
} catch (dbErr) {
  await client.query("ROLLBACK").catch(() => {});
  throw dbErr;
} finally {
  client.release();
}
  
} catch (err) {
console.error(
`[referral-review] Could not review ${row.stripe_session_id}:`,
err
);
}
}
}
async function sendFirstQualifiedReferralEmails() {
if (!resend) {
console.warn(
"[referral-review] RESEND_API_KEY is not configured. Approval emails are skipped."
);
return;
}
const { rows } = await pool.query(`
SELECT
r.id AS referral_row_id,
r.ref_code,
r.referral_approved_at,
s.email AS sponsor_email,
s.full_name AS sponsor_name,
COALESCE(s.lang, 'es') AS sponsor_lang
FROM stripe_checkout_access r
JOIN users s
ON UPPER(s.refid) = UPPER(r.ref_code)
WHERE r.referral_status = 'qualified'
AND r.referral_approval_email_sent_at IS NULL
AND r.id = (
SELECT r2.id
FROM stripe_checkout_access r2
WHERE UPPER(r2.ref_code) = UPPER(r.ref_code)
AND r2.referral_status = 'qualified'
ORDER BY
r2.referral_approved_at ASC NULLS LAST,
r2.id ASC
LIMIT 1
)
ORDER BY r.referral_approved_at ASC NULLS LAST;
`);
console.log(
`[referral-review] First-qualified emails pending: ${rows.length}`
);
for (const row of rows) {
const lang = row.sponsor_lang === "en" ? "en" : "es";
const dashboardUrl = `${SITE_URL}/dashboard.html`;
const name = escapeHtml(firstName(row.sponsor_name));
const subject =
  lang === "en"
    ? "Your first referral has been approved! ✅"
    : "¡Tu primer referido ha sido aprobado! ✅"; 
const html =
lang === "en"
? `
<div style="font-family:Arial,sans-serif;color:#222;line-height:1.65;max-width:640px;margin:0 auto;">
<h2 style="color:#111;">The Master Key Program</h2>
<p><strong>${name ? `${name}, y` : "Y"}our first referral has been approved! \u2705</strong></p>
<p>Your first referral has completed the verification period and is now marked as <strong>Qualified</strong>.</p>
<p>The associated referral reward is now approved and will be handled according to the applicable TMKP payout schedule.</p>
<p>You can review your referral activity and current status at any time from your Dashboard.</p>
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
<p><strong>${name ? `${name}, ¡t` : "¡T"}u primer referido ha sido aprobado! \u2705</strong></p>
<p>Tu primer referido completó el periodo de verificación y ahora está marcado como <strong>Calificado</strong>.</p>
<p>La recompensa correspondiente a este referido queda aprobada y será procesada conforme al calendario de pagos aplicable de TMKP.</p>
<p>Puedes consultar tu actividad de referidos y su estado actual en cualquier momento desde tu Dashboard.</p>
<p>
<a href="${dashboardUrl}"
style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:999px;font-weight:700;">
Ver mi Dashboard
</a>
</p>
<p>Gracias por compartir The Master Key Program.</p>
</div>
`;
const text =
lang === "en"
? `Your first referral has been approved!
Your first referral completed the verification period and is now Qualified.
The associated referral reward is approved and will be handled according to the applicable TMKP payout schedule.
Dashboard: ${dashboardUrl}`
: `¡Tu primer referido ha sido aprobado!
Tu primer referido completó el periodo de verificación y ahora está Calificado.
La recompensa correspondiente queda aprobada y será procesada conforme al calendario de pagos aplicable de TMKP.
Dashboard: ${dashboardUrl}`;
try {
const emailResult = await resend.emails.send(
{
from: "The Master Key <support@themasterkeyprogram.com>",
to: row.sponsor_email,
subject,
html,
text,
},
{
idempotencyKey: `tmkp-first-qualified-referral/${row.referral_row_id}`,
}
);
if (emailResult && emailResult.error) {
throw new Error(
emailResult.error.message || "Resend returned an email error."
);
}
await pool.query(
`
UPDATE stripe_checkout_access
SET referral_approval_email_sent_at = COALESCE(
referral_approval_email_sent_at,
NOW()
),
updated_at = NOW()
WHERE id = $1;
`,
[row.referral_row_id]
);
console.log(
`[referral-review] First-qualified email sent to ${row.sponsor_email}`
);
} catch (err) {
console.error(
`[referral-review] Could not send approval email to ${row.sponsor_email}:`,
err
);
}
}
}
async function main() {
console.log("[referral-review] Starting referral review.");
await qualifyDueReferrals();
await sendFirstQualifiedReferralEmails();
console.log("[referral-review] Finished.");
}
main()
.catch((err) => {
console.error("[referral-review] Fatal error:", err);
process.exitCode = 1;
})
.finally(async () => {
await pool.end().catch(() => {});
});
