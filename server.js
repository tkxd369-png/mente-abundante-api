// server.js - API Mente Abundante

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// ------------------------------------------------------
// CONFIGURACIÓN
// ------------------------------------------------------

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || "CAMBIA_ESTE_SECRETO";

if (!DATABASE_URL) {
  console.error("❌ Falta la variable de entorno DATABASE_URL");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cors());
app.use(express.json());

// ------------------------------------------------------
// HELPERS
// ------------------------------------------------------

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function buildUserResponse(row) {
  return {
    id: row.id,
    full_name: row.full_name,
    email: row.email,
    phone: row.phone,
    username: row.username,
    refid: row.refid,
    referredby: row.referredby,
    referrals: row.referrals ?? 0,
    created_at: row.created_at,
  };
}

// Middleware de autenticación
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ ok: false, error: "Token no presente." });
  }

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id };
    next();
  } catch (err) {
    console.error("JWT error:", err.message);
    return res.status(401).json({ ok: false, error: "Token inválido o expirado." });
  }
}

// ------------------------------------------------------
// ENDPOINTS
// ------------------------------------------------------

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ------------------------------------------------------
//  AUTH: CREAR CUENTA
// ------------------------------------------------------
// Espera body:
// {
//    fullName,
//    email,
//    phone,
//    password,
//    username (opcional),
//    refCode (opcional: REF del que invitó)
// }

app.post("/auth/create-account", async (req, res) => {
  try {
    const { fullName, email, phone, password, username, refCode } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        ok: false,
        error: "Nombre completo, email, teléfono y contraseña son requeridos.",
      });
    }

    // Normalizar
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();
    const cleanFullName = String(fullName).trim();

    // Generar username si no viene
    let finalUsername = username
      ? String(username).trim()
      : cleanEmail.split("@")[0];

    // Evitar espacios raros
    finalUsername = finalUsername.replace(/\s+/g, "").toLowerCase();

    // Generar REFID (username + últimos 3 dígitos del teléfono)
    const digits = cleanPhone.replace(/\D/g, "");
    const last3 = digits.slice(-3) || "000";
    const baseRef = finalUsername.replace(/\W/g, "").slice(0, 8).toUpperCase();
    const refid = baseRef + last3;

    // Hash de contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // Insertar usuario
    const insertSql = `
      INSERT INTO users (full_name, email, phone, username, password_hash, refid, referredby)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, full_name, email, phone, username, refid, referredby, referrals, created_at;
    `;
    const refBy = refCode ? String(refCode).trim().toUpperCase() : null;

    const result = await pool.query(insertSql, [
      cleanFullName,
      cleanEmail,
      cleanPhone,
      finalUsername,
      passwordHash,
      refid,
      refBy,
    ]);

    const newUser = result.rows[0];

    // Si hay refCode, intentamos incrementar referrals del que invitó
    if (refBy) {
      try {
        await pool.query(
          "UPDATE users SET referrals = COALESCE(referrals, 0) + 1 WHERE refid = $1",
          [refBy]
        );
      } catch (e) {
        console.warn("No se pudo actualizar referrals del referidor:", e.message);
      }
    }

    const token = createToken(newUser);

    return res.json({
      ok: true,
      token,
      user: buildUserResponse(newUser),
    });
  } catch (err) {
    console.error("Create-account error:", err);
    if (err.code === "23505") {
      return res.status(400).json({
        ok: false,
        error: "El email, username o refid ya están en uso.",
      });
    }
    return res.status(500).json({
      ok: false,
      error: "Error interno al crear la cuenta.",
    });
  }
});

// ------------------------------------------------------
//  AUTH: LOGIN
// ------------------------------------------------------
// body: { email, password }

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanEmail || !password) {
      return res
        .status(400)
        .json({ ok: false, error: "Email y contraseña son requeridos." });
    }

    const sql = `
      SELECT id, full_name, email, phone, username, refid, referredby,
             referrals, created_at, password_hash
      FROM users
      WHERE email = $1
      LIMIT 1;
    `;
    const result = await pool.query(sql, [cleanEmail]);

    if (result.rows.length === 0) {
      return res
        .status(400)
        .json({ ok: false, error: "Email o contraseña incorrectos." });
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res
        .status(400)
        .json({ ok: false, error: "Email o contraseña incorrectos." });
    }

    const token = createToken(user);

    return res.json({
      ok: true,
      token,
      user: buildUserResponse(user),
    });
  } catch (err) {
    console.error("Login error:", err);
    return res
      .status(500)
      .json({ ok: false, error: "Error interno al iniciar sesión." });
  }
});

// ------------------------------------------------------
//  /me - DATOS DEL USUARIO AUTENTICADO
// ------------------------------------------------------

app.get("/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const sql = `
      SELECT id, full_name, email, phone, username, refid, referredby,
             referrals, created_at
      FROM users
      WHERE id = $1;
    `;
    const result = await pool.query(sql, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Usuario no encontrado." });
    }

    const user = result.rows[0];

    return res.json({
      ok: true,
      user: buildUserResponse(user),
    });
  } catch (err) {
    console.error("/me error:", err);
    return res
      .status(500)
      .json({ ok: false, error: "Error interno al cargar el perfil." });
  }
});

// ------------------------------------------------------
//  ACTUALIZAR PERFIL: EMAIL Y/O TELÉFONO
// ------------------------------------------------------

app.post("/account/update-profile", authMiddleware, async (req, res) => {
  try {
    const { email, phone } = req.body;
    const userId = req.user.id;

    if (!email && !phone) {
      return res
        .status(400)
        .json({ ok: false, error: "Debes enviar al menos email o teléfono." });
    }

    const fields = [];
    const values = [];
    let index = 1;

    if (email) {
      fields.push(`email = $${index++}`);
      values.push(String(email).trim().toLowerCase());
    }
    if (phone) {
      fields.push(`phone = $${index++}`);
      values.push(String(phone).trim());
    }

    values.push(userId);

    const sql = `
      UPDATE users
      SET ${fields.join(", ")}
      WHERE id = $${index}
      RETURNING id, full_name, email, phone, username, refid, referredby,
                referrals, created_at;
    `;

    const result = await pool.query(sql, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Usuario no encontrado." });
    }

    const updatedUser = result.rows[0];

    return res.json({
      ok: true,
      user: buildUserResponse(updatedUser),
    });
  } catch (err) {
    console.error("Update profile error:", err);
    if (err.code === "23505") {
      return res.status(400).json({
        ok: false,
        error: "El email ya está en uso por otra cuenta.",
      });
    }
    return res
      .status(500)
      .json({ ok: false, error: "Error interno al actualizar el perfil." });
  }
});

// ------------------------------------------------------
//  CAMBIAR CONTRASEÑA
// ------------------------------------------------------
// body: { currentPassword, newPassword }

app.post("/account/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        ok: false,
        error: "Debes enviar la contraseña actual y la nueva.",
      });
    }

    const userResult = await pool.query(
      "SELECT id, password_hash FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Usuario no encontrado." });
    }

    const user = userResult.rows[0];

    const isValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValid) {
      return res
        .status(400)
        .json({ ok: false, error: "La contraseña actual no es correcta." });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
      newHash,
      userId,
    ]);

    return res.json({
      ok: true,
      message: "Contraseña actualizada correctamente.",
    });
  } catch (err) {
    console.error("Change password error:", err);
    return res
      .status(500)
      .json({ ok: false, error: "Error interno al cambiar la contraseña." });
  }
});

// ------------------------------------------------------
//  SERVER LISTEN
// ------------------------------------------------------

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log("✅ API Mente Abundante escuchando en el puerto " + port);
});
