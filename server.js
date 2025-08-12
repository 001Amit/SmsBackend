require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const morgan = require('morgan');
const http = require('http');
const { Server } = require('socket.io');
const connectDB = require('./config/db');
const Message = require('./models/Message');
const Admin = require('./models/Admin');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 4000;

(async () => {
  try {
    await connectDB(process.env.MONGO_URI);

    // Create admin from ENV if not exists
    const username = process.env.ADMIN_USERNAME;
    const password = process.env.ADMIN_PASSWORD;
    if (username && password) {
      const existing = await Admin.findOne({ username });
      if (!existing) {
        const hash = await bcrypt.hash(password, 12);
        await Admin.create({ username, passwordHash: hash });
        console.log('✅ Initial admin created');
      }
    }
  } catch (err) {
    console.error('❌ DB connection error:', err);
    process.exit(1);
  }
})();

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());
app.use(morgan('dev'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI, collectionName: 'sessions' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Rate limit for API
const messagesLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
});

// API key middleware
function checkApiKey(req, res, next) {
  const key = req.header('x-api-key') || req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
}

// API endpoint for receiving messages
app.post('/api/messages', messagesLimiter, checkApiKey, async (req, res) => {
  try {
    const { sender, message, timestamp } = req.body;
    if (!sender || !message) {
      return res.status(400).json({ error: 'sender and message required' });
    }

    const msg = await Message.create({
      sender,
      message,
      timestamp: timestamp ? new Date(timestamp) : undefined
    });

    // Emit to dashboard in real time
    io.emit('newMessage', {
      _id: msg._id,
      sender: msg.sender,
      message: msg.message,
      createdAt: msg.createdAt
    });

    res.status(201).json({ ok: true, id: msg._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Admin login/logout routes
app.get('/admin/login', (req, res) => res.render('login', { error: null }));

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin) return res.render('login', { error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, admin.passwordHash);
  if (!ok) return res.render('login', { error: 'Invalid credentials' });

  req.session.adminId = admin._id;
  res.redirect('/admin/dashboard');
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// Auth middleware
function requireAdmin(req, res, next) {
  if (!req.session?.adminId) return res.redirect('/admin/login');
  next();
}

// Dashboard view
app.get('/admin/dashboard', requireAdmin, async (req, res) => {
  const messages = await Message.find().sort({ createdAt: -1 }).limit(50).lean();
  res.render('dashboard', { messages });
});

// JSON endpoint for table refresh
app.get('/admin/messages-json', requireAdmin, async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 }).limit(50).lean();
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Delete a message
app.post('/admin/messages/:id/delete', requireAdmin, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.redirect('/admin/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to delete message');
  }
});

// Root
app.get('/', (req, res) => res.redirect('/admin/login'));

// Socket.IO connection logging
io.on('connection', () => console.log('📡 Dashboard connected'));

server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
