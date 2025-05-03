const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const port = 3000;

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database(':memory:');
const SECRET_KEY = 'your-secret-key'; // Replace with a secure key in production

app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// Initialize database
db.serialize(() => {
  db.run('CREATE TABLE users (email TEXT PRIMARY KEY, password TEXT)');
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
      if (err) {
        return res.status(400).json({ message: 'User already exists' });
      }
      res.status(201).json({ message: 'User registered' });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Token verification endpoint
app.get('/api/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ email: decoded.email });
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(port, () => {console.log('Server running on port 3000')});
app.use(express.static('docs'));