import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Ruta simple para probar
app.get('/health', async (req, res) => {
  try {
    // Opcional: probar conexión a DB
    await pool.query('SELECT 1');
    res.json({ ok: true, ts: Date.now() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log('API running on port ' + port));
