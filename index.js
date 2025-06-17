const express = require('express');
const https = require('https');
const fs = require('fs');
const cors = require('cors');
const session = require('express-session');
const sequelize = require('./config/sequelize');
const authRoutes = require('./routes/auth');

require('dotenv').config();

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('API is running securely ✅');
});

// Sync DB and start HTTPS server
sequelize.sync().then(() => {
  const httpsOptions = {
    key: fs.readFileSync('localhost-key.pem'),
    cert: fs.readFileSync('localhost.pem'),
  };

  https.createServer(httpsOptions, app).listen(3000, () => {
    console.log('Secure backend running at https://localhost:3000');
  });
});



(async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection has been established successfully.');
  } catch (error) {
    console.error('❌ Unable to connect to the database:', error);
  }
})();