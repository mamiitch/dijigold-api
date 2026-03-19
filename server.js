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
        user_name TEXT,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(firm_id, username)
      );
      CREATE TABLE IF NOT EXISTS dg_products (
        id SERIAL PRIMARY KEY,
        firm_id TEXT NOT NULL,
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
      CREATE TABLE IF NOT EXISTS dg_hurdalar (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, alim_no TEXT,
        customer_name TEXT DEFAULT '', karat TEXT DEFAULT '14',
        gram REAL DEFAULT 0, has_gram REAL DEFAULT 0, kur_fiyat REAL DEFAULT 0,
        toplam REAL DEFAULT 0, note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_doviz (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, doviz_cinsi TEXT DEFAULT 'USD',
        islem_tipi TEXT DEFAULT 'alis', miktar REAL DEFAULT 0, kur REAL DEFAULT 0,
        tl_tutar REAL DEFAULT 0, note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_giderler (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, gider_no TEXT,
        kategori TEXT DEFAULT 'diger', aciklama TEXT NOT NULL, tutar REAL DEFAULT 0,
        odeme_tipi TEXT DEFAULT 'nakit', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS dg_banka_hesaplari (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, hesap_name TEXT NOT NULL,
        balance REAL DEFAULT 0, hesap_type TEXT DEFAULT 'banka'
      );
      CREATE TABLE IF NOT EXISTS dg_rfid (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, tag_id TEXT NOT NULL,
        product_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(firm_id, tag_id)
      );
      CREATE TABLE IF NOT EXISTS dg_banka_log (
        id SERIAL PRIMARY KEY, firm_id TEXT NOT NULL, hesap_id INTEGER,
        log_date TIMESTAMP DEFAULT NOW(), description TEXT, log_type TEXT, amount REAL
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
      'INSERT INTO dg_users (firm_id, username, password, user_name, role) VALUES ($1,$2,$3,$4,$5)',
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
    res.json({ ok: true, token, user: { name: user.user_name, role: user.role, username: user.username } });
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


// ===== KASA =====
app.get('/kasa', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    // Satışlardan kasa bakiyesi hesapla
    const sales = await pool.query("SELECT COALESCE(SUM(total),0) AS total FROM dg_sales WHERE firm_id=$1 AND cancelled=false AND pay_type!='cari'", [fid]);
    const log = await pool.query("SELECT id, sale_date as log_date, sale_no as aciklama, pay_type as log_type, total as amount FROM dg_sales WHERE firm_id=$1 AND cancelled=false ORDER BY id DESC LIMIT 50", [fid]);
    res.json({ ok: true, balance: sales.rows[0].total, log: log.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});


// ===== HURDA ALIM =====
app.get('/hurdalar', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_hurdalar WHERE firm_id=$1 ORDER BY id DESC", [req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});
app.post('/hurdalar', authMiddleware, async (req, res) => {
  try {
    const h = req.body; const fid = req.user.firmId;
    const milyem = h.karat=='18'?0.750:h.karat=='22'?0.916:h.karat=='9'?0.375:0.585;
    const hasGram = (h.gram||0) * milyem;
    const toplam = hasGram * (h.kurFiyat||0);
    const cnt = await pool.query("SELECT COUNT(*)+1 AS no FROM dg_hurdalar WHERE firm_id=$1", [fid]);
    const no = `HRD-${new Date().getFullYear()}-${String(cnt.rows[0].no).padStart(4,'0')}`;
    await pool.query("INSERT INTO dg_hurdalar(firm_id,alim_no,customer_name,karat,gram,has_gram,kur_fiyat,toplam,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
      [fid,no,h.customerName||'',h.karat||'14',h.gram||0,hasGram,h.kurFiyat||0,toplam,h.note||'']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== DÖVİZ =====
app.get('/doviz', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_doviz WHERE firm_id=$1 ORDER BY id DESC", [req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});
app.post('/doviz', authMiddleware, async (req, res) => {
  try {
    const d = req.body; const fid = req.user.firmId;
    const tlTutar = (d.miktar||0) * (d.kur||0);
    await pool.query("INSERT INTO dg_doviz(firm_id,doviz_cinsi,islem_tipi,miktar,kur,tl_tutar,note) VALUES($1,$2,$3,$4,$5,$6,$7)",
      [fid,d.dovizCinsi||'USD',d.islemTipi||'alis',d.miktar||0,d.kur||0,tlTutar,d.note||'']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== GİDER =====
app.get('/giderler', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_giderler WHERE firm_id=$1 ORDER BY id DESC", [req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});
app.post('/giderler', authMiddleware, async (req, res) => {
  try {
    const g = req.body; const fid = req.user.firmId;
    const cnt = await pool.query("SELECT COUNT(*)+1 AS no FROM dg_giderler WHERE firm_id=$1", [fid]);
    const no = `GDR-${new Date().getFullYear()}-${String(cnt.rows[0].no).padStart(4,'0')}`;
    await pool.query("INSERT INTO dg_giderler(firm_id,gider_no,kategori,aciklama,tutar,odeme_tipi) VALUES($1,$2,$3,$4,$5,$6)",
      [fid,no,g.kategori||'diger',g.aciklama,g.tutar||0,g.odemeTipi||'nakit']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== HAS BİLANÇOSU =====
app.get('/has-bilancosu', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const r = await pool.query("SELECT karat, COALESCE(SUM(gram*stock),0) AS toplam_gram FROM dg_products WHERE firm_id=$1 AND stock>0 GROUP BY karat ORDER BY karat", [fid]);
    const milyemMap = {'8':0.333,'9':0.375,'14':0.585,'18':0.750,'22':0.916,'925':0.925};
    let toplamHas = 0;
    const satirlar = r.rows.map(p => {
      const milyem = milyemMap[String(p.karat)] || 0.585;
      const hasGram = parseFloat(p.toplam_gram) * milyem;
      toplamHas += hasGram;
      return { karat: String(p.karat), toplamGram: parseFloat(p.toplam_gram), milyem, hasGram };
    });
    const hurda = await pool.query("SELECT COALESCE(SUM(has_gram),0) AS toplam FROM dg_hurdalar WHERE firm_id=$1", [fid]);
    const hurdaHas = parseFloat(hurda.rows[0].toplam) || 0;
    res.json({ ok: true, data: satirlar, toplamHas: parseFloat(toplamHas.toFixed(3)), hurdaHas: parseFloat(hurdaHas.toFixed(3)) });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== BANKA =====
app.get('/banka', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const hesaplar = await pool.query("SELECT * FROM dg_banka_hesaplari WHERE firm_id=$1 ORDER BY id", [fid]);
    const log = await pool.query("SELECT * FROM dg_banka_log WHERE firm_id=$1 ORDER BY id DESC LIMIT 50", [fid]);
    res.json({ ok: true, hesaplar: hesaplar.rows, log: log.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ===== RAPOR =====
app.get('/rapor', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const { tip, baslangic, bitis } = req.query;
    let data = {};
    if (tip === 'satis') {
      const r = await pool.query("SELECT * FROM dg_sales WHERE firm_id=$1 AND cancelled=false AND DATE(sale_date)>=$2 AND DATE(sale_date)<=$3 ORDER BY id DESC", [fid, baslangic, bitis]);
      data.satirlar = r.rows;
      data.toplam = r.rows.reduce((a,b)=>a+(parseFloat(b.total)||0),0);
      data.nakit = r.rows.filter(s=>s.pay_type==='nakit').reduce((a,b)=>a+(parseFloat(b.total)||0),0);
      data.kart = r.rows.filter(s=>s.pay_type==='kart').reduce((a,b)=>a+(parseFloat(b.total)||0),0);
    } else if (tip === 'gider') {
      const r = await pool.query("SELECT * FROM dg_giderler WHERE firm_id=$1 AND DATE(created_at)>=$2 AND DATE(created_at)<=$3 ORDER BY id DESC", [fid, baslangic, bitis]);
      data.satirlar = r.rows;
      data.toplam = r.rows.reduce((a,b)=>a+(parseFloat(b.tutar)||0),0);
    }
    res.json({ ok: true, data });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});


// ===== EK ENDPOINT'LER =====

// Stok güncelle
app.patch('/products/:id/stock', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE dg_products SET stock=stock+$1,updated_at=NOW() WHERE id=$2 AND firm_id=$3", [req.body.amount, req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Satış iptal
app.patch('/sales/:id/cancel', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE dg_sales SET cancelled=true WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Kasa işlem
app.post('/kasa', authMiddleware, async (req, res) => {
  try {
    const { type, amount, desc } = req.body;
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Tamir tek getir
app.get('/tamirler/:id', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_tamirler WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true, data: r.rows[0] || {} });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Tamir sil
app.delete('/tamirler/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_tamirler WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Sipariş tek getir
app.get('/siparisler/:id', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM dg_siparisler WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true, data: r.rows[0] || {} });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Sipariş sil
app.delete('/siparisler/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_siparisler WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Hurda sil
app.delete('/hurdalar/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_hurdalar WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Gider sil
app.delete('/giderler/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_giderler WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Döviz sil
app.delete('/doviz/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_doviz WHERE id=$1 AND firm_id=$2", [req.params.id, req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Banka işlem
app.post('/banka/islem', authMiddleware, async (req, res) => {
  try {
    const { hesapId, type, amount, desc } = req.body;
    const fid = req.user.firmId;
    if (type==='in') await pool.query("UPDATE dg_banka_hesaplari SET balance=balance+$1 WHERE id=$2 AND firm_id=$3",[amount,hesapId,fid]);
    else await pool.query("UPDATE dg_banka_hesaplari SET balance=GREATEST(0,balance-$1) WHERE id=$2 AND firm_id=$3",[amount,hesapId,fid]);
    await pool.query("INSERT INTO dg_banka_log(firm_id,hesap_id,description,log_type,amount) VALUES($1,$2,$3,$4,$5)",[fid,hesapId,desc,type,amount]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Banka hesap ekle
app.post('/banka/hesap', authMiddleware, async (req, res) => {
  try {
    const { Name, Type } = req.body;
    await pool.query("INSERT INTO dg_banka_hesaplari(firm_id,hesap_name,hesap_type) VALUES($1,$2,$3)",[req.user.firmId,Name,Type||'banka']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Müşteri ekstre
app.get('/musteri-ekstre/:id', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const m = await pool.query("SELECT * FROM dg_customers WHERE id=$1 AND firm_id=$2",[req.params.id,fid]);
    const s = await pool.query("SELECT * FROM dg_sales WHERE customer_id=$1 AND firm_id=$2 AND cancelled=false ORDER BY id DESC",[req.params.id,fid]);
    const t = await pool.query("SELECT * FROM dg_tamirler WHERE customer_id=$1 AND firm_id=$2 ORDER BY id DESC",[req.params.id,fid]);
    const sp = await pool.query("SELECT * FROM dg_siparisler WHERE customer_id=$1 AND firm_id=$2 ORDER BY id DESC",[req.params.id,fid]);
    if (!m.rows.length) return res.json({ ok: false, error: 'Müşteri bulunamadı' });
    res.json({ ok: true, musteri: m.rows[0], satislar: s.rows, tamirler: t.rows, siparisler: sp.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Dashboard grafik
app.get('/dashboard-grafik', authMiddleware, async (req, res) => {
  try {
    const fid = req.user.firmId;
    const son7gun = [];
    for (let i=6; i>=0; i--) {
      const d = new Date(); d.setDate(d.getDate()-i);
      const tarih = d.toISOString().split('T')[0];
      const s = await pool.query("SELECT COALESCE(SUM(total),0) AS toplam FROM dg_sales WHERE firm_id=$1 AND cancelled=false AND DATE(sale_date)=$2",[fid,tarih]);
      const g = await pool.query("SELECT COALESCE(SUM(tutar),0) AS toplam FROM dg_giderler WHERE firm_id=$1 AND DATE(created_at)=$2",[fid,tarih]);
      son7gun.push({ tarih: tarih.slice(5), satis: s.rows[0].toplam, gider: g.rows[0].toplam });
    }
    res.json({ ok: true, data: son7gun });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// RFID
app.get('/rfid', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT rf.*,p.name as product_name,p.karat,p.stock FROM dg_rfid rf JOIN dg_products p ON rf.product_id=p.id WHERE rf.firm_id=$1 ORDER BY rf.id DESC",[req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/rfid', authMiddleware, async (req, res) => {
  try {
    const { tagId, productId } = req.body;
    await pool.query("INSERT INTO dg_rfid(firm_id,tag_id,product_id) VALUES($1,$2,$3) ON CONFLICT(firm_id,tag_id) DO UPDATE SET product_id=$3",[req.user.firmId,tagId,productId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/rfid/:tagId', authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM dg_rfid WHERE tag_id=$1 AND firm_id=$2",[req.params.tagId,req.user.firmId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.get('/rfid/find/:tagId', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT rf.*,p.name,p.karat,p.gram,p.stock,p.price FROM dg_rfid rf JOIN dg_products p ON rf.product_id=p.id WHERE rf.tag_id=$1 AND rf.firm_id=$2",[req.params.tagId,req.user.firmId]);
    res.json({ ok: true, data: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Health check
app.get('/', (req, res) => res.json({ ok: true, service: 'DijiGold API', version: '1.0.0' }));

setupDB().then(() => {
  app.listen(PORT, () => console.log(`DijiGold API çalışıyor, port: ${PORT}`));
}).catch(e => { console.error('DB bağlantı hatası:', e.message); process.exit(1); });