import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Pool de conexión a Neon con SSL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Helper: crear token
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.JWT_SECRET || 'dev_secret',
    { expiresIn: '7d' }
  );
}

// Middleware de autenticación
async function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const [, token] = auth.split(' '); // "Bearer token"

    if (!token) {
      return res.status(401).json({ ok: false, error: 'Token requerido.' });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'dev_secret'
    );

    // Cargar usuario desde la BD
    const result = await pool.query(
      'SELECT id, full_name, email, phone, username, refId, referredBy, referrals, created_at FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ ok: false, error: 'Usuario no encontrado.' });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    return res.status(401).json({ ok: false, error: 'Token inválido o expirado.' });
  }
}

// Ruta de prueba
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, ts: Date.now() });
  } catch (err) {
    console.error('DB error:', err.message);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// ✅ Ruta para crear cuenta
app.post('/auth/create-account', async (req, res) => {
  try {
    const { name, email, phone, username, password, referredBy } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email y contraseña son requeridos.' });
    }

    // sugerir username si viene vacío
    let finalUsername = username && username.trim();
    if (!finalUsername) {
      const base = (name || 'usuario').split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
      const rand = Math.floor(100 + Math.random() * 900); // 3 dígitos
      finalUsername = (base || 'user') + rand;
    }

    // generar refId a partir del username
    const refId = finalUsername.toUpperCase().slice(0, 8);

    // hash de contraseña
    const hash = await bcrypt.hash(password, 10);

    // guardar en DB
    const insertUser = `
      INSERT INTO users(full_name, email, phone, password_hash, username, refId, referredBy)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING id, full_name, email, phone, username, refId, referredBy, referrals, created_at;
    `;

    const values = [name || null, email, phone || null, hash, finalUsername, refId, referredBy || null];

    const result = await pool.query(insertUser, values);
    const user = result.rows[0];

    // si hay referredBy, registramos en tabla referrals
    if (referredBy) {
      await pool.query(
        'INSERT INTO referrals(refId, newUserEmail) VALUES ($1,$2)',
        [referredBy, email]
      );
      await pool.query(
        'UPDATE users SET referrals = referrals + 1 WHERE refId = $1',
        [referredBy]
      );
    }

    const token = createToken(user);

    return res.json({
      ok: true,
      user,
      token,
    });
  } catch (err) {
    console.error('Create account error:', err.message);
    if (err.code === '23505') {
      // unique_violation (email o username repetido)
      return res.status(400).json({ ok: false, error: 'Email o usuario ya existen.' });
    }
    return res.status(500).json({ ok: false, error: 'Error interno al crear la cuenta.' });
  }
});

// ✅ Ruta de login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email y contraseña son requeridos.' });
    }

    const result = await pool.query(
      'SELECT id, full_name, email, phone, username, refId, referredBy, referrals, password_hash, created_at FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ ok: false, error: 'Credenciales inválidas.' });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ ok: false, error: 'Credenciales inválidas.' });
    }

    // quitar password_hash de la respuesta
    delete user.password_hash;

    const token = createToken(user);

    return res.json({
      ok: true,
      user,
      token,
    });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ ok: false, error: 'Error interno al iniciar sesión.' });
  }
});

// ✅ Ruta /me (datos del usuario logueado)
app.get('/me', authMiddleware, (req, res) => {
  return res.json({
    ok: true,
    user: req.user,
  });
});

// 👇 IMPORTANTE: app.listen SIEMPRE VA AL FINAL
const port = process.env.PORT || 8080;
app.listen(port, () => console.log('API running on port ' + port));
