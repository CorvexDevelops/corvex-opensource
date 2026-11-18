// Demo project WRITTEN WELL, for benchmarking scanners: no line here should become a finding.
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { execFile } = require('child_process');
const crypto = require('crypto');
const mysql = require('mysql2');

const app = express();
app.use(helmet());
app.use(cors({ origin: 'https://shop.example', credentials: true }));
const db = mysql.createPool({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD });

// Signed-in users only: the signed token says who the customer is.
function requireLogin(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch (e) {
    res.sendStatus(401);
  }
}

// Each customer sees only their own orders: the id comes from the token, never from the request.
app.get('/orders', requireLogin, async (req, res) => {
  const [rows] = await db.promise().query('SELECT * FROM orders WHERE customer = ?', [req.user.id]);
  res.json(rows);
});

app.get('/convert', (req, res) => {
  const name = String(req.query.file || '');
  if (!/^[\w-]+\.png$/.test(name)) return res.sendStatus(400);
  execFile('convert', [name, 'out.png'], () => res.send('done'));
});

app.get('/profile', (req, res) => {
  const data = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  res.json({ role: data.role });
});

app.post('/invite', (req, res) => {
  const inviteCode = crypto.randomBytes(16).toString('hex');
  res.json({ inviteCode });
});

// Only a UI animation: randomness protects nothing here.
const animationDelay = () => 200 + Math.random() * 100;

app.listen(3000, '127.0.0.1');
module.exports = { animationDelay };
