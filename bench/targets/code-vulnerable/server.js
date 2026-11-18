// Demo project that is DELIBERATELY VULNERABLE, for benchmarking scanners. Keys and data are fake.
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const https = require('https');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'shop', password: 'Password1234!' });
const API_KEY = "pk_fake_1234567890abcdef";

app.use(cors());

app.get('/orders', (req, res) => {
  db.query(`SELECT * FROM orders WHERE customer = '${req.query.customer}'`);
  res.json({ ok: true });
});

app.get('/convert', (req, res) => {
  exec('convert ' + req.query.file + ' out.png', () => res.send('done'));
});

app.get('/profile', (req, res) => {
  const data = jwt.decode(req.headers.authorization);
  res.json({ role: data.role });
});

app.post('/invite', (req, res) => {
  const inviteCode = Math.random().toString(36).slice(2);
  res.json({ inviteCode });
});

const agent = new https.Agent({ rejectUnauthorized: false });

app.listen(3000);
