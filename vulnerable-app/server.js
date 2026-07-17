/**
 * DELIBERATELY VULNERABLE APP — FOR TESTING/DEMO ONLY.
 * This app exists solely as a target for the AI Red-Team-in-a-Box scanner.
 * Never deploy this publicly or use these patterns in real code.
 */

const express = require('express');
const sqlite3 = require('sqlite3');
const path = require('path');
const { exec } = require('child_process');
const http = require('http');

const app = express();

// Enable wide open CORS for hackathon dashboard connectivity
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Global variable representing Shield / Secure Mode
let secureMode = false;

// In-memory DB
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)`);
  db.run(`INSERT INTO users VALUES (1,'admin','admin123','admin')`);
  db.run(`INSERT INTO users VALUES (2,'bob','bobpass','user')`);
});

// Security state toggle endpoints
app.get('/api/security-status', (req, res) => {
  res.json({ secure: secureMode });
});

app.post('/api/toggle-security', (req, res) => {
  const { secure } = req.body || {};
  if (typeof secure === 'boolean') {
    secureMode = secure;
  } else {
    secureMode = !secureMode;
  }
  res.json({ success: true, secure: secureMode });
});

// BUG 1: SQL Injection -> POST /login
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  
  if (secureMode) {
    // SECURE: Parameterized query prevents injection
    db.get(`SELECT * FROM users WHERE username=? AND password=?`, [username, password], (err, row) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      if (row) return res.json({ success: true, user: { id: row.id, username: row.username, role: row.role } });
      return res.status(401).json({ success: false });
    });
  } else {
    // VULNERABLE: Direct string concatenation
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    db.get(query, (err, row) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      if (row) return res.json({ success: true, user: row });
      return res.status(401).json({ success: false });
    });
  }
});

// BUG 2: IDOR -> GET /api/user/:id
app.get('/api/user/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const mockCurrentUserRole = req.headers['x-user-role'] || 'user';
  const mockCurrentUserId = parseInt(req.headers['x-user-id'] || '2', 10);

  if (secureMode) {
    // SECURE: Verify owner access or admin privileges
    if (mockCurrentUserRole !== 'admin' && mockCurrentUserId !== id) {
      return res.status(403).json({ error: 'Access denied: unauthorized object access' });
    }
  }

  db.get(`SELECT id, username, role FROM users WHERE id=?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json(row || null);
  });
});

// BUG 3: Broken Access Control -> GET /admin/users
app.get('/admin/users', (req, res) => {
  if (secureMode) {
    // SECURE: Explicit authorization token check
    const authHeader = req.headers['authorization'];
    if (!authHeader || authHeader !== 'Bearer admin-token-1337') {
      return res.status(401).json({ error: 'Unauthorized: Admin privileges required' });
    }
  }

  db.all(`SELECT id, username, role FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json(rows);
  });
});

// BUG 4: Reflected XSS -> GET /comment
app.get('/comment', (req, res) => {
  const text = req.query.text || '';
  if (secureMode) {
    // SECURE: HTML Entity encoding to neutralize payloads
    const escaped = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
    res.send(`<html><body><h3>You said: ${escaped}</h3></body></html>`);
  } else {
    // VULNERABLE: Direct insertion
    res.send(`<html><body><h3>You said: ${text}</h3></body></html>`);
  }
});

// BUG 5: Path Traversal -> GET /api/file
app.get('/api/file', (req, res) => {
  const filename = req.query.name || '';
  const baseDir = path.resolve(__dirname);
  const targetPath = path.resolve(baseDir, filename);

  if (secureMode) {
    // SECURE: Verify that the resolved path is strictly within the base folder
    if (!targetPath.startsWith(baseDir)) {
      return res.status(403).json({ error: 'Forbidden: Path traversal attempt detected' });
    }
  }

  res.sendFile(targetPath, (err) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    }
  });
});

// BUG 6: Command Injection -> POST /api/ping
app.post('/api/ping', (req, res) => {
  const ip = req.body.ip || '';

  if (secureMode) {
    // SECURE: Strictly validate input is a standard IPv4 address
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipv4Regex.test(ip.trim())) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }
  }

  // Run a system ping check command
  const pingCommand = process.platform === 'win32' ? `ping -n 1 ${ip}` : `ping -c 1 ${ip}`;

  exec(pingCommand, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message, output: stderr || stdout });
    }
    res.json({ success: true, output: stdout });
  });
});

// BUG 7: SSRF -> GET /api/fetch-url
app.get('/api/fetch-url', (req, res) => {
  const targetUrl = req.query.url || '';

  if (secureMode) {
    // SECURE: Block requests targeting localhost, 127.0.0.1, or local networks
    try {
      const parsedUrl = new URL(targetUrl);
      const hostname = parsedUrl.hostname.toLowerCase();
      if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
        return res.status(403).json({ error: 'Forbidden: Requesting internal infrastructure is blocked' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
  }

  // Fetch requested url content
  http.get(targetUrl, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => {
      res.json({ success: true, status: response.statusCode, content: data.slice(0, 1000) });
    });
  }).on('error', (err) => {
    res.status(502).json({ error: `Fetch failed: ${err.message}` });
  });
});

app.get('/', (req, res) => {
  res.send('AI Red-Team target app is online. Shield Mode is ' + (secureMode ? 'ENABLED' : 'DISABLED') + '.');
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Vulnerable app listening on :${PORT}`));
