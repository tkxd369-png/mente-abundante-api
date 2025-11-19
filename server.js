 import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
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
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, ts: Date.now() });
  } catch (err) {
    console.error('DB error:', err.message);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log('API running on port ' + port));
