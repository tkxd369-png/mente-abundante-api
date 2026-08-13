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
console.error("nn Falta DATABASE_URL en .env");
}
if (!process.env.JWT_SECRET) {
console.error("nn Falta JWT_SECRET en .env");
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
// Consumir la compra. Desde este momento este sessionId ya no
// puede utilizarse para crear otra cuenta.
const consumeResult = await client.query(
`
UPDATE stripe_checkout_access
SET signup_used = TRUE,
signup_used_at = NOW(),
updated_at = NOW()
WHERE stripe_session_id = $1
AND signup_used = FALSE;
`,
[String(sessionId).trim()]
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
const { email, phone } = req.body || {};
if (!email && !phone) {
return res.status(400).json({
ok: false,
error: "Nada para actualizar (email o teléfono requeridos)",
});
}
const fields = [];
const values = [];
let idx = 1;
if (email) {
fields.push(`email = $${idx++}`);
values.push(String(email).trim().toLowerCase());
}
if (phone) {
fields.push(`phone = $${idx++}`);
values.push(normalizePhone(phone));
}
values.push(userId);
const query = `
UPDATE users
SET ${fields.join(", ")}
WHERE id = $${idx}
RETURNING *;
`;
const { rows } = await pool.query(query, values);
if (rows.length === 0) {
return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
}
const updatedUser = buildUserResponse(rows[0]);
return res.json({
ok: true,
user: updatedUser,
});
} catch (err) {
console.error("POST /account/update-profile error:", err);
return res.status(500).json({ ok: false, error: "Server error" });
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
const diff = await pool.query(`SELECT EXTRACT(EPOCH FROM (($1::timestamptz + INTERVAL '60 minutes') - NOW()))::int AS s;`,
[oldestTs]);
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
console.log(`n Mente Abundante API escuchando en el puerto ${PORT}`);
}); 
