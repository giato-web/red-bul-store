import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import pg from 'pg';
import connectPgSimple from 'connect-pg-simple';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import Stripe from 'stripe';

const app = express();
const PORT = process.env.PORT || 10000;
const Pool = pg.Pool;
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Copy .env.example to .env and configure PostgreSQL.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD) {
  console.error('SESSION_SECRET and ADMIN_PASSWORD must be configured.');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});
const PgSession = connectPgSimple(session);
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const uploadsDir = path.join(process.cwd(), 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { if (req.originalUrl === '/api/stripe/webhook') req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'redbul.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/uploads', express.static(uploadsDir, { maxAge: '1d' }));
app.use(express.static(path.join(process.cwd(), 'public')));

const q = (text, values=[]) => pool.query(text, values);
const adminOnly = (req, res, next) => req.session?.admin ? next() : res.status(401).json({ error: 'سجّل دخول المدير أولاً.' });
const currency = (process.env.CURRENCY || 'USD').toUpperCase();
const storeName = process.env.STORE_NAME || 'RED BUL';

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    price_cents INTEGER NOT NULL CHECK(price_cents >= 0), image_url TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'رقمي', active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY, customer_email TEXT NOT NULL, items JSONB NOT NULL,
    total_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    payment_method TEXT NOT NULL DEFAULT 'manual', payment_reference TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS licenses (
    id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    code TEXT NOT NULL UNIQUE, duration_days INTEGER NOT NULL DEFAULT 30,
    max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}
const money = n => (Number(n) / 100).toFixed(2);
const publicProduct = p => ({ ...p, price: money(p.price_cents), price_cents: Number(p.price_cents) });
app.get('/api/health', (_req,res) => res.json({ ok:true, store:storeName }));
app.get('/api/config', (_req,res) => res.json({ storeName, currency, onlinePayments: !!stripe }));

app.get('/api/products', async (_req,res,next) => {
  try {
    const { rows } = await q('SELECT * FROM products WHERE active = TRUE ORDER BY created_at DESC');
    res.json(rows.map(publicProduct));
  } catch(e) { next(e); }
});

app.post('/api/admin/login', async (req,res,next) => {
  try {
    const { username, password } = req.body || {};
    const expectedUser = process.env.ADMIN_USERNAME || 'admin';
    const expectedPassword = process.env.ADMIN_PASSWORD;
    if (username !== expectedUser || !await bcrypt.compare(String(password || ''), await bcrypt.hash(expectedPassword, 10))) {
      // Compare against configured secret without storing it in the database.
      if (username !== expectedUser || !crypto.timingSafeEqual(
        Buffer.from(String(password || '').padEnd(256).slice(0,256)),
        Buffer.from(String(expectedPassword || '').padEnd(256).slice(0,256))
      )) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
    }
    req.session.admin = true;
    res.json({ ok:true });
  } catch(e) { next(e); }
});
app.post('/api/admin/logout', adminOnly, (req,res) => req.session.destroy(() => res.json({ ok:true })));
app.get('/api/admin/me', (req,res) => res.json({ authenticated: !!req.session?.admin }));

const storage = multer.diskStorage({
  destination: (_req,_file,cb) => cb(null, uploadsDir),
  filename: (_req,file,cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase())
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req,file,cb) => cb(null, ['image/jpeg','image/png','image/webp','image/gif'].includes(file.mimetype))
});
app.post('/api/admin/upload', adminOnly, upload.single('image'), (req,res) => {
  if (!req.file) return res.status(400).json({ error: 'اختر صورة JPG أو PNG أو WEBP أو GIF بحجم أقل من 5MB.' });
  res.json({ image_url: `/uploads/${req.file.filename}` });
});

app.get('/api/admin/products', adminOnly, async (_req,res,next) => {
  try { const { rows } = await q('SELECT * FROM products ORDER BY created_at DESC'); res.json(rows.map(publicProduct)); } catch(e) { next(e); }
});
app.post('/api/admin/products', adminOnly, async (req,res,next) => {
  try {
    const { name, description='', price, image_url='', category='رقمي', active=true } = req.body || {};
    const amount = Math.round(Number(price) * 100);
    if (!name?.trim() || !Number.isFinite(amount) || amount < 0 || amount > 100000000) return res.status(400).json({error:'أدخل اسمًا وسعرًا صحيحًا.'});
    const { rows } = await q('INSERT INTO products(name,description,price_cents,image_url,category,active) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [name.trim(),String(description).slice(0,3000),amount,String(image_url).slice(0,1000),String(category).slice(0,100),!!active]);
    res.status(201).json(publicProduct(rows[0]));
  } catch(e) { next(e); }
});
app.put('/api/admin/products/:id', adminOnly, async (req,res,next) => {
  try {
    const { name, description='', price, image_url='', category='رقمي', active=true } = req.body || {};
    const amount = Math.round(Number(price) * 100);
    if (!name?.trim() || !Number.isFinite(amount) || amount < 0) return res.status(400).json({error:'أدخل اسمًا وسعرًا صحيحًا.'});
    const { rows } = await q('UPDATE products SET name=$1,description=$2,price_cents=$3,image_url=$4,category=$5,active=$6 WHERE id=$7 RETURNING *',
      [name.trim(),String(description).slice(0,3000),amount,String(image_url).slice(0,1000),String(category).slice(0,100),!!active,req.params.id]);
    if (!rows[0]) return res.status(404).json({error:'المنتج غير موجود.'});
    res.json(publicProduct(rows[0]));
  } catch(e) { next(e); }
});
app.delete('/api/admin/products/:id', adminOnly, async (req,res,next) => {
  try { await q('DELETE FROM products WHERE id=$1',[req.params.id]); res.json({ok:true}); } catch(e) { next(e); }
});

app.post('/api/orders', async (req,res,next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const method = req.body?.payment_method === 'online' ? 'online' : 'manual';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !items.length || items.length > 30) return res.status(400).json({error:'تحقق من البريد والمنتجات.'});
    const ids = [...new Set(items.map(x => Number(x.id)).filter(Number.isInteger))];
    const { rows: products } = await q('SELECT id,name,price_cents FROM products WHERE active=TRUE AND id=ANY($1::int[])',[ids]);
    if (!products.length || products.length !== ids.length) return res.status(400).json({error:'أحد المنتجات غير متاح.'});
    const normalized = products.map(p => ({ id:p.id, name:p.name, quantity: Math.max(1,Math.min(10,Number(items.find(i=>Number(i.id)===p.id)?.quantity)||1)), unit_price_cents:Number(p.price_cents) }));
    const total = normalized.reduce((sum,p)=>sum+p.unit_price_cents*p.quantity,0);
    if (method === 'online' && !stripe) return res.status(400).json({error:'الدفع الإلكتروني غير مفعّل بعد. اختر الدفع اليدوي أو أضف مفاتيح Stripe في إعدادات الاستضافة.'});
    const { rows } = await q('INSERT INTO orders(customer_email,items,total_cents,status,payment_method) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [email,JSON.stringify(normalized),total,method==='online'?'awaiting_payment':'pending',method]);
    if (method === 'online') {
      const base = process.env.BASE_URL;
      if (!base) return res.status(500).json({error:'BASE_URL غير مضبوط.'});
      const checkout = await stripe.checkout.sessions.create({
        mode:'payment', customer_email:email,
        line_items: normalized.map(p=>({quantity:p.quantity,price_data:{currency:currency.toLowerCase(),unit_amount:p.unit_price_cents,product_data:{name:p.name}}})),
        success_url:`${base}/?payment=success&order=${rows[0].id}`, cancel_url:`${base}/?payment=cancelled`,
        metadata:{order_id:String(rows[0].id)}
      });
      await q('UPDATE orders SET payment_reference=$1 WHERE id=$2',[checkout.id,rows[0].id]);
      return res.json({checkout_url:checkout.url,order_id:rows[0].id});
    }
    res.status(201).json({ok:true,order_id:rows[0].id,message:'تم تسجيل الطلب. تواصل مع المتجر لإتمام الدفع اليدوي.'});
  } catch(e) { next(e); }
});

app.post('/api/stripe/webhook', async (req,res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(400).send('Stripe webhook not configured');
  let event;
  try { event = stripe.webhooks.constructEvent(req.rawBody,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET); }
  catch(err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
  if (event.type === 'checkout.session.completed') {
    const sessionObj = event.data.object;
    await q("UPDATE orders SET status='paid' WHERE id=$1 AND payment_reference=$2",[sessionObj.metadata.order_id,sessionObj.id]);
  }
  res.json({received:true});
});

app.get('/api/admin/orders', adminOnly, async (_req,res,next) => {
  try { const { rows } = await q('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500'); res.json(rows.map(o=>({...o,total:money(o.total_cents)}))); } catch(e) { next(e); }
});
app.patch('/api/admin/orders/:id', adminOnly, async (req,res,next) => {
  try {
    const allowed = ['pending','awaiting_payment','paid','fulfilled','cancelled'];
    if (!allowed.includes(req.body?.status)) return res.status(400).json({error:'حالة غير صالحة.'});
    const { rows } = await q('UPDATE orders SET status=$1 WHERE id=$2 RETURNING *',[req.body.status,req.params.id]);
    if (!rows[0]) return res.status(404).json({error:'الطلب غير موجود.'});
    res.json({...rows[0],total:money(rows[0].total_cents)});
  } catch(e) { next(e); }
});

app.get('/api/admin/licenses', adminOnly, async (_req,res,next) => {
  try { const { rows } = await q('SELECT l.*,p.name AS product_name FROM licenses l LEFT JOIN products p ON p.id=l.product_id ORDER BY l.created_at DESC LIMIT 500'); res.json(rows); } catch(e) { next(e); }
});
app.post('/api/admin/licenses', adminOnly, async (req,res,next) => {
  try {
    const productId = req.body?.product_id ? Number(req.body.product_id) : null;
    const days = Math.max(1,Math.min(3650,Number(req.body?.duration_days)||30));
    const maxUses = Math.max(1,Math.min(10000,Number(req.body?.max_uses)||1));
    const count = Math.max(1,Math.min(100,Number(req.body?.count)||1));
    const codes = [];
    for(let i=0;i<count;i++) {
      const code = `RB-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      const { rows } = await q('INSERT INTO licenses(product_id,code,duration_days,max_uses) VALUES($1,$2,$3,$4) RETURNING *',[productId,code,days,maxUses]);
      codes.push(rows[0]);
    }
    res.status(201).json(codes);
  } catch(e) { next(e); }
});
app.patch('/api/admin/licenses/:id', adminOnly, async (req,res,next) => {
  try { const { rows } = await q('UPDATE licenses SET active=$1 WHERE id=$2 RETURNING *',[!!req.body?.active,req.params.id]); if(!rows[0]) return res.status(404).json({error:'الرخصة غير موجودة.'}); res.json(rows[0]); } catch(e) { next(e); }
});
app.post('/api/licenses/validate', async (req,res,next) => {
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();
    const { rows } = await q('SELECT * FROM licenses WHERE code=$1',[code]);
    const l = rows[0];
    if(!l || !l.active || l.uses >= l.max_uses || (l.expires_at && new Date(l.expires_at)<new Date())) return res.json({valid:false,message:'الكود غير صالح أو انتهى.'});
    res.json({valid:true,message:'الكود صالح.',duration_days:l.duration_days});
  } catch(e) { next(e); }
});

app.get('/admin', (_req,res) => res.sendFile(path.join(process.cwd(),'public','admin.html')));
app.use((err,_req,res,_next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).json({error:'تعذر رفع الصورة. تأكد من الحجم (5MB كحد أقصى).'});
  res.status(500).json({error:'حدث خطأ في الخادم. راجع سجلات الاستضافة.'});
});

initDb().then(() => app.listen(PORT,'0.0.0.0',()=>console.log(`${storeName} running on port ${PORT}`)))
  .catch(err=>{ console.error('Database initialization failed:',err); process.exit(1); });
