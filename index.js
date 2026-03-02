const express = require('express');
const app = express();
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');

/* ========================
   GLOBAL MIDDLEWARE
======================== */

app.use(compression());

app.set('trust proxy', 1);
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000, // biar ga gampang 429
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

/* ========================
   ROUTES
======================== */

/**
 * 1️⃣ LOGIN DASHBOARD (GET)
 * Harus return HTML
 */
app.all('/player/login/dashboard', (req, res) => {
  console.log('valKey:', req.query.valKey || 'none');

  return res.render('dashboard', {
    token: require('crypto').randomBytes(16).toString('hex')
  });
});

/**
 * 2️⃣ VALIDATE LOGIN (POST)
 */
app.post('/player/growid/login/validate', (req, res) => {
  try {
    const { _token, growId, password } = req.body;

    if (!_token || !growId || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields',
      });
    }

    const tokenRaw = `_token=${_token}&growId=${growId}&password=${password}`;
    const token = Buffer.from(tokenRaw).toString('base64');

    return res.status(200).json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (err) {
    console.error('Validate Error:', err);
    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * 3️⃣ CHECK TOKEN (POST)
 */
app.post('/player/growid/checkToken', (req, res) => {
  try {
    const { refreshToken, clientData } = req.body;

    if (!refreshToken || !clientData) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
    }

    const decoded = Buffer.from(refreshToken, 'base64').toString('utf8');

    const updated = decoded.replace(
      /(_token=)[^&]*/,
      `$1${Buffer.from(clientData).toString('base64')}`
    );

    const newToken = Buffer.from(updated).toString('base64');

    return res.status(200).json({
      status: 'success',
      message: 'Token is valid.',
      token: newToken,
      url: '',
      accountType: 'growtopia',
    });
  } catch (err) {
    console.error('CheckToken Error:', err);
    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/* ========================
   DEFAULT ROUTES
======================== */

app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'favicon.ico'));
});

app.get('/', (req, res) => {
  res.status(200).send('Growtopia Login Backend Running');
});

/* ========================
   404 HANDLER
======================== */

app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Route Not Found',
  });
});

/* ========================
   ERROR HANDLER
======================== */

app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({
    status: 'error',
    message: 'Unexpected Server Error',
  });
});

/* ========================
   START SERVER
======================== */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
