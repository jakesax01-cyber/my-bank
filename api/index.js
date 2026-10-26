const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'my_secret_123456_demo_only';

// Init DB tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      full_name TEXT,
      balance DECIMAL DEFAULT 0,
      status TEXT DEFAULT 'pending',
      otp1 TEXT,
      otp2 TEXT,
      otp3 TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      type TEXT,
      amount DECIMAL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}
initDB();

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({error:'No token'});
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e){ res.status(401).json({error:'Invalid token'}); }
}

// API check
app.get('/api', (req,res)=>{
  res.json({message:'Bank API Running as per requirements - Demo Project'});
});

// Signup
app.post('/api/auth/signup', async (req,res)=>{
  try{
    const {email,password,full_name}=req.body;
    const hash = await bcrypt.hash(password,10);
    const result = await pool.query('INSERT INTO users(email,password,full_name,balance,status) VALUES($1,$2,$3,0,$4) RETURNING id,email,full_name,balance,status',[email,hash,full_name,'pending']);
    const token = jwt.sign({id:result.rows[0].id,email},JWT_SECRET,{expiresIn:'7d'});
    res.json({token,user:result.rows[0]});
  }catch(e){ res.status(400).json({error:e.message}); }
});

// Login
app.post('/api/auth/login', async (req,res)=>{
  try{
    const {email,password}=req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    if(result.rows.length==0) return res.status(400).json({error:'User not found'});
    const user = result.rows[0];
    const ok = await bcrypt.compare(password,user.password);
    if(!ok) return res.status(400).json({error:'Wrong password'});
    const token = jwt.sign({id:user.id,email:user.email,isAdmin:email==='admin@demo.com'},JWT_SECRET,{expiresIn:'7d'});
    res.json({token,user:{id:user.id,email:user.email,full_name:user.full_name,balance:user.balance,status:user.status,otp1:user.otp1,otp2:user.otp2,otp3:user.otp3}});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Get profile
app.get('/api/user/me', auth, async (req,res)=>{
  const r = await pool.query('SELECT id,email,full_name,balance,status,otp1,otp2,otp3 FROM users WHERE id=$1',[req.user.id]);
  res.json(r.rows[0]);
});

// Withdraw with OTP
app.post('/api/withdraw', auth, async (req,res)=>{
  try{
    const {amount,otp} = req.body;
    const r = await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]);
    const user = r.rows[0];
    if(user.status!=='approved') return res.status(400).json({error:'Account not approved by admin - pending'});
    if(parseFloat(user.balance) < parseFloat(amount)) return res.status(400).json({error:'Insufficient balance'});
    if(otp !== user.otp1 && otp !== user.otp2 && otp !== user.otp3) return res.status(400).json({error:'Invalid OTP - ask admin for correct OTP'});
    
    await pool.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[amount,req.user.id]);
    await pool.query('INSERT INTO transactions(user_id,type,amount,description) VALUES($1,$2,$3,$4)',[req.user.id,'withdraw',amount,'Withdrawal with OTP']);
    res.json({message:'Withdrawal successful'});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Admin - get all users
app.get('/api/admin/users', auth, async (req,res)=>{
  const r = await pool.query('SELECT id,email,full_name,balance,status,otp1,otp2,otp3 FROM users ORDER BY id DESC');
  res.json(r.rows);
});

// Admin - approve/decline/pending
app.post('/api/admin/status', auth, async (req,res)=>{
  const {userId,status}=req.body;
  await pool.query('UPDATE users SET status=$1 WHERE id=$2',[status,userId]);
  res.json({message:'Status updated to '+status});
});

// Admin - assign OTPs
app.post('/api/admin/otp', auth, async (req,res)=>{
  const {userId,otp1,otp2,otp3}=req.body;
  await pool.query('UPDATE users SET otp1=$1,otp2=$2,otp3=$3 WHERE id=$4',[otp1,otp2,otp3,userId]);
  res.json({message:'OTPs assigned'});
});

// Admin - credit/debit with balance check
app.post('/api/admin/transaction', auth, async (req,res)=>{
  try{
    const {userId,type,amount,description}=req.body;
    if(type==='credit'){
      await pool.query('UPDATE users SET balance=balance+$1 WHERE id=$2',[amount,userId]);
    }else{
      const r = await pool.query('SELECT balance FROM users WHERE id=$1',[userId]);
      if(parseFloat(r.rows[0].balance) < parseFloat(amount)) return res.status(400).json({error:'Insufficient balance - cannot debit'});
      await pool.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[amount,userId]);
    }
    await pool.query('INSERT INTO transactions(user_id,type,amount,description) VALUES($1,$2,$3,$4)',[userId,type,amount,description||type]);
    res.json({message:type+' successful'});
  }catch(e){ res.status(500).json({error:e.message}); }
});

module.exports = app;
