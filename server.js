 require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const app = express();
const Resend = require("resend").Resend;
const resend = new Resend(process.env.RESEND_API_KEY);
const paymentsRouter = require("./routes/payments");
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
password,
username: usernameRaw,
} = req.body || {};
if (!sessionId || !String(sessionId).startsWith("cs_")) {
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
signup_used
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
if (referredby) {
await client.query(
`
UPDATE users
SET referrals = COALESCE(referrals, 0) + 1
WHERE UPPER(refid) = $1;
`,
[referredby]
);
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
COALESCE(referrals, 0)::int AS referrals,
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
