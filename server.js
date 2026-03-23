require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcrypt');
const validator = require('validator');
const speakeasy = require('speakeasy');
const si = require('systeminformation');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new sqlite3.Database('./game.db');


db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      otp_secret TEXT,
      email TEXT,
      ip TEXT,
      is_banned INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER,
      expires_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS blacklist (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      blocked_until INTEGER
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      message TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});

async function deepSystemCheck() {
  try {
    const os = await si.osInfo();
    const cpu = await si.cpu();
    const mem = await si.mem();
    const fs = await si.fsSize();

    if (mem.used > mem.total * 0.9) {
      console.error('❗ Критическая загрузка памяти.');
      process.exit(1);
    }
    if (fs.some(disk => disk.use > 90)) {
      console.error('❗ Диск почти заполнен.');
      process.exit(1);
    }
    console.log('✅ Системная проверка пройдена.');
  } catch (err) {
    console.error('Ошибка системной проверки:', err);
    process.exit(1);
  }
}

async function checkDependencies() {
  const { exec } = require('child_process');
  exec('npm audit --production --json', (err, stdout) => {
    if (err) {
      console.error('❗ Уязвимости в зависимостях:', err);
      process.exit(1);
    } else {
      const result = JSON.parse(stdout);
      if (result.vulnerabilities.total > 0) {
        console.error('❗ Найденные уязвимости:', result.vulnerabilities);
        process.exit(1);
      }
      console.log('✅ Зависимости проверены.');
    }
  });
}

app.use(helmet({
  hsts: false,
  xssFilter: true,
  noSniff: true
}));
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json({ limit: '10kb' }));


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Слишком много запросов.'
});
app.use('/api/', limiter);

function checkBlacklist(req, res, next) {
  const ip = req.ip;
  db.get(
    'SELECT * FROM blacklist WHERE ip = ? AND blocked_until > ?',
    [ip, Date.now()],
    (err, row) => {
      if (row) return res.status(403).json({ error: 'Доступ запрещён.' });
      next();
    }
  );
}
app.use(checkBlacklist);

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

function generateOTPSecret() {
  return speakeasy.generateSecret({ length: 20 }).base32;
}

function verifyOTP(secret, token) {
  return speakeasy.totp.verify({ secret, encoding: 'base32', token });
}

app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Все поля обязательны.' });
  }
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return res.status(400).json({ error: 'Имя 3–20 символов.' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Некорректный email.' });
  }

  try {
    const passwordHash = await hashPassword(password);
    const otpSecret = generateOTPSecret();
    const ip = req.ip;

    db.run(
      'INSERT INTO users (username, password_hash, otp_secret, email, ip) VALUES (?, ?, ?, ?, ?)',
      [username, passwordHash, otpSecret, email, ip],
      function (err) {
        if (err && err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Пользователь существует.' });
        }
        if (err) return res.status(500).json({ error: 'Ошибка БД.' });
        res.status(201).json({ success: true, username });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Ошибка хеширования.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны.' });
  }

  db.get
    ('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Не
            {
  "name": "secure-server",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "ws": "^8.13.0",
    "sqlite3": "^5.1.7",
    "rate-limit": "^6.7.0",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "bcrypt": "^5.1.1",
    "validator": "^13.11.0",
    "speakeasy": "^2.0.3",
    "systeminformation": "^5.10.0"