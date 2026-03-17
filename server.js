const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL || 'postgresql://postgres:oKJFjzrdJAKFencnUBxswDFzbTWmdNij@hopper.proxy.rlwy.net:41810/railway';
const JWT_SECRET = process.env.JWT_SECRET || 'dijigold-secret-2026';

const pool = new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });

app.use(cors());
app.use(express.json());

// ===== VERİTABANI KURULUM =====
async function setupDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS dg_users (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(firm_id, username)
      );
      CREATE TABLE IF NOT EXISTS dg_products (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        source_id TEXT,
        barcode TEXT DEFAULT '',
        name TEXT NOT NULL,
        category TEXT DEFAULT '',
        karat TEXT DEFAULT '14',
        gram DECIMAL(10,3) DEFAULT 0,
        stock INTEGER DEFAULT 0,
        min_stock INTEGER DEFAULT 1,
        price DECIMAL(18,2) DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_customers (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        source_id TEXT,
        name TEXT NOT NULL,
        phone TEXT DEFAULT '',
        address TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        balance DECIMAL(18,2) DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_sales (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        sale_no TEXT,
        sale_date TIMESTAMP DEFAULT NOW(),
        customer_id INTEGER,
        customer_name TEXT DEFAULT 'Perakende',
        items TEXT DEFAULT '',
        total_gram DECIMAL(10,3) DEFAULT 0,
        pay_type TEXT DEFAULT 'nakit',
        total DECIMAL(18,2) DEFAULT 0,
        note TEXT DEFAULT '',
        cancelled BOOLEAN DEFAULT FALSE
      );
      CREATE TABLE IF NOT EXISTS dg_settings (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT,
        UNIQUE(firm_id, key)
      );
      CREATE TABLE IF NOT EXISTS dg_tamirler (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        tamir_no TEXT,
        customer_id INTEGER,
        customer_name TEXT DEFAULT '',
        product_desc TEXT,
        fault TEXT DEFAULT '',
        fee DECIMAL(18,2) DEFAULT 0,
        due_date TEXT DEFAULT '',
        status TEXT DEFAULT 'bekliyor',
        note TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_siparisler (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
        siparis_no TEXT,
        customer_id INTEGER,
        customer_name TEXT DEFAULT '',
        aciklama TEXT,
        karat TEXT DEFAULT '14',
        gram DECIMAL(10,3) DEFAULT 0,
        ucret DECIMAL(18,2) DEFAULT 0,
        kapora DECIMAL(18,2) DEFAULT 0,
        teslim_tarihi TEXT DEFAULT '',
        status TEXT DEFAULT 'bekliyor',
        note TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Backfill / migrate for existing deployments
    await client.query(`
      ALTER TABLE dg_products ADD COLUMN IF NOT EXISTS source_id TEXT;
      ALTER TABLE dg_customers ADD COLUMN IF NOT EXISTS source_id TEXT;
      CREATE UNIQUE INDEX IF NOT EXISTS dg_products_firm_source_uidx ON dg_products (firm_id, source_id);
      CREATE UNIQUE INDEX IF NOT EXISTS dg_customers_firm_source_uidx ON dg_customers (firm_id, source_id);
    `);
    console.log('Veritabanı tabloları hazır');
  } finally {
    client.release();
  }
}

// ===== AUTH MİDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ ok: false, error: 'Token gerekli' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ ok: false, error: 'Geçersiz token' });
  }
}

// ===== AUTH ROUTES =====
// Firma kaydı / ilk kurulum
app.post('/auth/register', async (req, res) => {
  try {
    const { firmId, username, password, name } = req.body;
    if (!firmId || !username || !password) return res.json({ ok: false, error: 'Eksik bilgi' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO dg_users (firm_id, username, password, name, role) VALUES ($1,$2,$3,$4,$5)',
      [firmId, username, hash, name || 'Admin', 'admin']
    );
    res.json({ ok: true });
  } catch(e) {
    if (e.code === '23505') return res.json({ ok: false, error: 'Bu kullanıcı adı zaten kayıtlı' });
    res.json({ ok: false, error: e.message });
  }
});

// Giriş
app.post('/auth/login', async (req, res) => {
  try {
    const { firmId, username, password } = req.body;
    const result = await pool.query(
      'SELECT * FROM dg_users WHERE firm_id=$1 AND username=$2', [firmId, username]
    );
    if (!result.rows.length) return res.json({ ok: false, error: 'Kullanıcı bulunamadı' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ ok: false, error: 'Şifre hatalı' });
    const token = jwt.sign({ userId: user.id, firmId: user.firm_id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ ok: true, token, user: { name: user.name, role: user.role, username: user.username } });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== DASHBOARD =====
app.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const today = new Date().toISOString().split('T')[0];
    const ts = await pool.query("SELECT COUNT(*) AS cnt, COALESCE(SUM(total),0) AS total, COALESCE(SUM(total_gram),0) AS gram FROM dg_sales WHERE firm_id=$1 AND cancelled=false AND DATE(sale_date)=$2", [fid, today]);
    const ls = await pool.query("SELECT COUNT(*) AS cnt FROM dg_products WHERE firm_id=$1 AND stock<=min_stock", [fid]);
    const rs = await pool.query("SELECT * FROM dg_sales WHERE firm_id=$1 AND cancelled=false ORDER BY id DESC LIMIT 8", [fid]);
    const tam = await pool.query("SELECT COUNT(*) AS cnt FROM dg_tamirler WHERE firm_id=$1 AND status!='teslim'", [fid]);
    const sip = await pool.query("SELECT COUNT(*) AS cnt FROM dg_siparisler WHERE firm_id=$1 AND status!='teslim'", [fid]);
    res.json({ ok: true, todayCount: ts.rows[0].cnt, todayTotal: ts.rows[0].total, todayGram: ts.rows[0].gram,
      lowStockCount: ls.rows[0].cnt, recentSales: rs.rows, activeTamir: tam.rows[0].cnt, activeSiparis: sip.rows[0].cnt });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== ÜRÜNLER =====
app.get('/products', authMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    let q, p;
    if (search) {
      q = "SELECT * FROM dg_products WHERE firm_id=$1 AND (name ILIKE $2 OR barcode ILIKE $2) ORDER BY name";
      p = [req.user.firmId, `%${search}%`];
    } else {
      q = "SELECT * FROM dg_products WHERE firm_id=$1 ORDER BY name";
      p = [req.user.firmId];
    }
    const r = await pool.query(q, p);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/products', authMiddleware, async (req, res) => {
  try {
    const p = req.body; const fid = req.user.firmId;
    if (p.id) {
      await pool.query("UPDATE dg_products SET barcode=$1,name=$2,category=$3,karat=$4,gram=$5,stock=$6,min_stock=$7,price=$8,updated_at=NOW() WHERE id=$9 AND firm_id=$10",
        [p.barcode||'',p.name,p.category||'',p.karat||'14',p.gram||0,p.stock||0,p.min_stock||1,p.price||0,p.id,fid]);
    } else {
      await pool.query("INSERT INTO dg_products(firm_id,barcode,name,category,karat,gram,stock,min_stock,price) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        [fid,p.barcode||'',p.name,p.category||'',p.karat||'14',p.gram||0,p.stock||0,p.min_stock||1,p.price||0]);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/products/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_products WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== MÜŞTERİLER =====
app.get('/customers', authMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    let q, p;
    if (search) { q = "SELECT * FROM dg_customers WHERE firm_id=$1 AND (name ILIKE $2 OR phone ILIKE $2) ORDER BY name"; p = [req.user.firmId, `%${search}%`]; }
    else { q = "SELECT * FROM dg_customers WHERE firm_id=$1 ORDER BY name"; p = [req.user.firmId]; }
    const r = await pool.query(q, p);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/customers', authMiddleware, async (req, res) => {
  try {
    const c = req.body; const fid = req.user.firmId;
    if (c.id) {
      await pool.query("UPDATE dg_customers SET name=$1,phone=$2,address=$3,notes=$4,balance=$5,updated_at=NOW() WHERE id=$6 AND firm_id=$7",
        [c.name,c.phone||'',c.address||'',c.notes||'',c.balance||0,c.id,fid]);
    } else {
      await pool.query("INSERT INTO dg_customers(firm_id,name,phone,address,notes) VALUES($1,$2,$3,$4,$5)",
        [fid,c.name,c.phone||'',c.address||'',c.notes||'']);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/customers/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_customers WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== SATIŞLAR =====
app.get('/sales', authMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    let q, p;
    if (search) { q = "SELECT * FROM dg_sales WHERE firm_id=$1 AND cancelled=false AND (sale_no ILIKE $2 OR customer_name ILIKE $2) ORDER BY id DESC"; p = [req.user.firmId, `%${search}%`]; }
    else { q = "SELECT * FROM dg_sales WHERE firm_id=$1 AND cancelled=false ORDER BY id DESC LIMIT 100"; p = [req.user.firmId]; }
    const r = await pool.query(q, p);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/sales', authMiddleware, async (req, res) => {
  try {
    const sale = req.body; const fid = req.user.firmId;
    const cnt = await pool.query("SELECT COUNT(*)+1 AS no FROM dg_sales WHERE firm_id=$1", [fid]);
    const saleNo = `SAT-${new Date().getFullYear()}-${String(cnt.rows[0].no).padStart(4,'0')}`;
    await pool.query("INSERT INTO dg_sales(firm_id,sale_no,customer_id,customer_name,items,total_gram,pay_type,total,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
      [fid,saleNo,sale.customerId||null,sale.customer||'Perakende',(sale.items||'').substring(0,1000),sale.totalGram||0,sale.pay||'nakit',sale.total||0,sale.note||'']);
    // Stok düş
    for (const item of (sale.cartItems||[])) {
      await pool.query("UPDATE dg_products SET stock=stock-$1,updated_at=NOW() WHERE id=$2 AND firm_id=$3", [item.qty, item.pid, fid]);
    }
    res.json({ ok: true, saleNo });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== TAMİR =====
app.get('/tamirler', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_tamirler WHERE firm_id=$1 ORDER BY id DESC", [req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/tamirler', authMiddleware, async (req, res) => {
  try {
    const t = req.body; const fid = req.user.firmId;
    if (t.id) {
      await pool.query("UPDATE dg_tamirler SET customer_id=$1,product_desc=$2,fault=$3,fee=$4,due_date=$5,status=$6,note=$7 WHERE id=$8 AND firm_id=$9",
        [t.customerId||null,t.productDesc,t.fault||'',t.fee||0,t.dueDate||'',t.status||'bekliyor',t.note||'',t.id,fid]);
    } else {
      const cnt = await pool.query("SELECT COUNT(*)+1 AS no FROM dg_tamirler WHERE firm_id=$1", [fid]);
      const no = `TAM-${new Date().getFullYear()}-${String(cnt.rows[0].no).padStart(4,'0')}`;
      let custName = t.customerName || '';
      await pool.query("INSERT INTO dg_tamirler(firm_id,tamir_no,customer_id,customer_name,product_desc,fault,fee,due_date,status,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        [fid,no,t.customerId||null,custName,t.productDesc,t.fault||'',t.fee||0,t.dueDate||'',t.status||'bekliyor',t.note||'']);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.patch('/tamirler/:id/durum', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE dg_tamirler SET status=$1 WHERE id=$2 AND firm_id=$3", [req.body.status, req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== SİPARİŞLER =====
app.get('/siparisler', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_siparisler WHERE firm_id=$1 ORDER BY id DESC", [req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/siparisler', authMiddleware, async (req, res) => {
  try {
    const s = req.body; const fid = req.user.firmId;
    if (s.id) {
      await pool.query("UPDATE dg_siparisler SET customer_id=$1,aciklama=$2,karat=$3,gram=$4,ucret=$5,kapora=$6,teslim_tarihi=$7,status=$8,note=$9 WHERE id=$10 AND firm_id=$11",
        [s.customerId||null,s.aciklama,s.karat||'14',s.gram||0,s.ucret||0,s.kapora||0,s.teslimTarihi||'',s.status||'bekliyor',s.note||'',s.id,fid]);
    } else {
      const cnt = await pool.query("SELECT COUNT(*)+1 AS no FROM dg_siparisler WHERE firm_id=$1", [fid]);
      const no = `SIP-${new Date().getFullYear()}-${String(cnt.rows[0].no).padStart(4,'0')}`;
      await pool.query("INSERT INTO dg_siparisler(firm_id,siparis_no,customer_id,customer_name,aciklama,karat,gram,ucret,kapora,teslim_tarihi,status,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        [fid,no,s.customerId||null,s.customerName||'',s.aciklama,s.karat||'14',s.gram||0,s.ucret||0,s.kapora||0,s.teslimTarihi||'',s.status||'bekliyor',s.note||'']);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.patch('/siparisler/:id/durum', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE dg_siparisler SET status=$1 WHERE id=$2 AND firm_id=$3", [req.body.status, req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== AYARLAR =====
app.get('/settings', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT key,value FROM dg_settings WHERE firm_id=$1", [req.user.firmId]);
    const obj = {}; r.rows.forEach(row => { obj[row.key] = row.value; });
    res.json({ ok: true, data: obj });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/settings', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    for (const [k, v] of Object.entries(req.body)) {
      await pool.query("INSERT INTO dg_settings(firm_id,key,value) VALUES($1,$2,$3) ON CONFLICT(firm_id,key) DO UPDATE SET value=$3",
        [fid, k, String(v)]);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== SYNC (Phase 1: desktop -> cloud push) =====
// Desktop sends its local integer IDs as `sourceId` (string/number).
// We upsert by (firm_id, source_id) so re-sending is safe.
app.post('/sync/push', authMiddleware, async (req, res) => {
  const fid = req.user.firmId;
  const { products = [], customers = [] } = req.body || {};

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const p of products) {
      const sourceId = p.sourceId ?? p.source_id ?? p.id ?? null;
      if (!sourceId) continue;
      await client.query(
        `
        INSERT INTO dg_products (firm_id, source_id, barcode, name, category, karat, gram, stock, min_stock, price, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
        ON CONFLICT (firm_id, source_id)
        DO UPDATE SET
          barcode=EXCLUDED.barcode,
          name=EXCLUDED.name,
          category=EXCLUDED.category,
          karat=EXCLUDED.karat,
          gram=EXCLUDED.gram,
          stock=EXCLUDED.stock,
          min_stock=EXCLUDED.min_stock,
          price=EXCLUDED.price,
          updated_at=NOW()
        `,
        [
          fid,
          String(sourceId),
          p.barcode || '',
          p.name,
          p.category || '',
          p.karat || '14',
          p.gram || 0,
          p.stock || 0,
          p.min_stock ?? p.minStock ?? 1,
          p.price || 0
        ]
      );
    }

    for (const c of customers) {
      const sourceId = c.sourceId ?? c.source_id ?? c.id ?? null;
      if (!sourceId) continue;
      await client.query(
        `
        INSERT INTO dg_customers (firm_id, source_id, name, phone, address, notes, balance, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
        ON CONFLICT (firm_id, source_id)
        DO UPDATE SET
          name=EXCLUDED.name,
          phone=EXCLUDED.phone,
          address=EXCLUDED.address,
          notes=EXCLUDED.notes,
          balance=EXCLUDED.balance,
          updated_at=NOW()
        `,
        [
          fid,
          String(sourceId),
          c.name,
          c.phone || '',
          c.address || '',
          c.notes || '',
          c.balance || 0
        ]
      );
    }

    await client.query('COMMIT');
    res.json({ ok: true, pushed: { products: products.length, customers: customers.length } });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    res.json({ ok: false, error: e.message });
  } finally {
    client.release();
  }
});

// Health check
app.get('/', (req, res) => res.json({ ok: true, service: 'DijiGold API', version: '1.0.0' }));

setupDB().then(() => {
  app.listen(PORT, () => console.log(`DijiGold API çalışıyor, port: ${PORT}`));
}).catch(e => { console.error('DB bağlantı hatası:', e.message); process.exit(1); });
