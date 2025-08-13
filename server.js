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
const Forwarder = require('./models/Forwarder');
const Message = require('./models/Message');
const Admin = require('./models/Admin');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 4000;
const PAGE_SIZE = 50;

// Pass io to app for API routes to use
app.set('io', io);

// Connect to DB and ensure admin exists
(async () => {
  try {
    await connectDB(process.env.MONGO_URI);
    console.log('✅ MongoDB Connected');

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
// Trust the first proxy (e.g., Railway, Heroku)
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());
app.use(morgan('dev'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

// Sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions'
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
  })
);

// Rate limiting
const messagesLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

// API key middleware
function checkApiKey(req, res, next) {
  const key = req.header('x-api-key') || req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== process.env.API_KEY)
    return res.status(401).json({ error: 'Invalid or missing API key' });
  next();
}

// --- /api/messages route (dual-SIM safe) ---
app.post('/api/messages', messagesLimiter, checkApiKey, async (req, res) => {
  try {
    const { sender, message, deviceId, deviceSim1, deviceSim2, timestamp } = req.body;

    if (!sender || !message || !deviceId) {
      return res.status(400).json({ error: 'sender, message, deviceId are required' });
    }

    const sim1 = deviceSim1?.trim() || null;
    const sim2 = deviceSim2?.trim() || null;

    // Validation
    if (sim1 && sim1.length !== 10) return res.status(400).json({ error: 'SIM1 must be 10 digits' });
    if (sim2 && sim2.length !== 10) return res.status(400).json({ error: 'SIM2 must be 10 digits' });
    if (sim1 && sim2 && sim1 === sim2) return res.status(400).json({ error: 'SIM1 and SIM2 cannot be the same' });

    // Save message
    const msg = await Message.create({
      sender,
      message,
      deviceId,
      deviceSim1: sim1,
      deviceSim2: sim2,
      timestamp: timestamp ? new Date(timestamp) : undefined
    });

    // Update Forwarder safely
    const numbersToAdd = [sim1, sim2].filter(Boolean);
    await Forwarder.findOneAndUpdate(
      { deviceId },
      {
        $set: { active: true, updatedAt: new Date() },
        $addToSet: { activeNumbers: { $each: numbersToAdd } }
      },
      { upsert: true, new: true }
    );

    // Emit live update
    io.emit('newMessage', {
      _id: msg._id,
      sender: msg.sender,
      message: msg.message,
      deviceSim1: msg.deviceSim1,
      deviceSim2: msg.deviceSim2,
      deviceId: msg.deviceId,
      createdAt: msg.createdAt
    });

    res.status(201).json({ ok: true, id: msg._id });
  } catch (err) {
    console.error('Error in /api/messages:', err);
    res.status(500).json({ error: 'server error' });
  }
});

// --- Admin authentication ---
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
app.get('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/admin/login')));

// --- Admin middleware ---
function requireAdmin(req, res, next) {
  if (!req.session?.adminId) return res.redirect('/admin/login');
  next();
}

// --- Admin dashboard ---
app.get('/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;

    const totalMessages = await Message.countDocuments().catch(() => 0);
    const totalPages = Math.ceil(totalMessages / PAGE_SIZE);
    const currentPage = Math.min(page, totalPages || 1);

    const messages = await Message.find()
      .sort({ createdAt: -1 })
      .skip((currentPage - 1) * PAGE_SIZE)
      .limit(PAGE_SIZE)
      .lean()
      .catch(() => []);

    const forwarders = await Forwarder.find({ active: true }).lean().catch(() => []);
    const activeNumbers = [...new Set(forwarders.flatMap(fwd => fwd.activeNumbers || []))];

    res.render('dashboard', {
      messages: messages || [],
      activeNumbers: activeNumbers || [],
      selectedNumber: null,
      currentPage,
      totalPages
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('Server error');
  }
});

// --- Filter messages by active number ---
app.get('/admin/activeNumbers/:number', requireAdmin, async (req, res) => {
  try {
    const { number } = req.params;
    const messages = await Message.find({
      $or: [{ deviceSim1: number }, { deviceSim2: number }]
    })
      .sort({ createdAt: -1 })
      .lean()
      .catch(() => []);

    const forwarders = await Forwarder.find({ active: true }).lean().catch(() => []);
    const activeNumbers = [...new Set(forwarders.flatMap(fwd => fwd.activeNumbers || []))];

    res.render('dashboard', {
      messages: messages || [],
      activeNumbers: activeNumbers || [],
      selectedNumber: number,
      currentPage: 1,
      totalPages: 1
    });
  } catch (err) {
    console.error('Filter error:', err);
    res.status(500).send('Server error');
  }
});

// --- Delete message ---
app.post('/admin/messages/:id/delete', requireAdmin, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.redirect('/admin/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to delete message');
  }
});

// --- Root redirect ---
app.get('/', (req, res) => res.redirect('/admin/login'));

// --- Socket.io connection ---
io.on('connection', socket => console.log('📡 Dashboard connected'));

// --- Start server ---
server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
