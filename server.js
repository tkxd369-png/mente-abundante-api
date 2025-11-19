import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import bcrypt from 'bcrypt';
const { Pool } = pkg;
 

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.get('/health', async (req, res) => {
 // Crear cuenta (primer versión sin SMS ni email todavía)
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
      RETURNING id, full_name, email, phone, username, refId, referredBy, created_at;
    `;

    const values = [name || null, email, phone || null, hash, finalUsername, refId, referredBy || null];

    const result = await pool.query(insertUser, values);
    const user = result.rows[0];

    // si hay referredBy, registramos en tabla referrals (primera versión sencilla)
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

    return res.json({
      ok: true,
      user,
    });
  } catch (err) {
    console.error('Create account error:', err.message);
    if (err.code === '23505') {
      // unique_violation
      return res.status(400).json({ ok: false, error: 'Email o usuario ya existen.' });
    }
    return res.status(500).json({ ok: false, error: 'Error interno al crear la cuenta.' });
  }
});
