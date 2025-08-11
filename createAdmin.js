// createAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Admin = require('./models/Admin');

async function run() {
  await mongoose.connect(process.env.MONGO_URI);
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) {
    console.error('Set ADMIN_USERNAME and ADMIN_PASSWORD in .env');
    process.exit(1);
  }
  const hash = await bcrypt.hash(password, 12);
  await Admin.updateOne({ username }, { username, passwordHash: hash }, { upsert: true });
  console.log('Admin created/updated');
  process.exit(0);
}
run().catch(err => { console.error(err); process.exit(1); });
