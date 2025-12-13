 require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// -------------------------
// Configuración de servidor
// -------------------------
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("⚠️ Falta DATABASE_URL en .env");
}
if (!process.env.JWT_SECRET) {
  console.error("⚠️ Falta JWT_SECRET en .env");
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
app.use(express.json());

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
// AUTH: Crear cuenta
// -------------------------

app.post("/auth/create-account", async (req, res) => {
  try {
 const {
  fullName,
  email,
  phone,
  password,
  username: usernameRaw,
  refCode,
  lang,         // 👈 nuevo
  country,  
} = req.body || {};


    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        ok: false,
        error: "Nombre completo, email, teléfono y contraseña son requeridos",
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedFullName = String(fullName).trim();
    const normalizedPhone = normalizePhone(phone);
    let username =
      (usernameRaw && String(usernameRaw).trim().toLowerCase()) ||
      usernameFromEmail(normalizedEmail);

    if (!username) {
      username = `user${Date.now()}`;
    }

    // Verificar si ya existe email o username
    const existing = await pool.query(
      "SELECT id, email, username FROM users WHERE email = $1 OR username = $2 LIMIT 1",
      [normalizedEmail, username]
    );

    if (existing.rows.length > 0) {
      const conflict = existing.rows[0];
      if (conflict.email === normalizedEmail) {
        return res
          .status(409)
          .json({ ok: false, error: "Este correo ya está registrado." });
      }
      if (conflict.username === username) {
        return res
          .status(409)
          .json({ ok: false, error: "Este nombre de usuario ya está en uso." });
      }
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Generar refid
    const refid = generateRefId(username, normalizedPhone);

    // Preparar referredby (refCode)
    const referredby = refCode ? String(refCode).trim().toUpperCase() : null;
    // Insertar usuario
    // idioma normalizado: si no viene "en", usamos "es"
    const userLang = (lang || "").toLowerCase() === "en" ? "en" : "es";

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
  country || null
];

    const { rows } = await pool.query(insertQuery, insertValues);
    const newUser = rows[0];

   
    // Si hay refCode, sumar 1 al patrocinador
    if (referredby) {
      try {
        await pool.query(
          `
          UPDATE users
          SET referrals = COALESCE(referrals, 0) + 1
          WHERE refid = $1;
        `,
          [referredby]
        );
      } catch (errRef) {
        console.error("Error actualizando referrals del patrocinador:", errRef);
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
    console.error("POST /auth/create-account error:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
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
  { phase: 1, limitPerHour: 100, price: 497, reward: 177.30, maxPayments: 1000 },
  { phase: 2, limitPerHour: 200, price: 777, reward: 177.30, maxPayments: 10000 },
  { phase: 3, limitPerHour: 300, price: 1270, reward: 250.00, maxPayments: 40000 },
  { phase: 4, limitPerHour: 400, price: 1970, reward: 447.00, maxPayments: null },
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

app.listen(PORT, () => {
  console.log(`✅ Mente Abundante API escuchando en el puerto ${PORT}`);
});
