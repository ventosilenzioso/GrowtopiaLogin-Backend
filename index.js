const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5000;

// @note trust proxy - set to number of proxies in front of app
app.set('trust proxy', 1);

// @note middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// @note rate limiter - 50 requests per minute
const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

// @note static files from public folder
app.use(express.static(path.join(process.cwd(), 'public')));

// @note request logging middleware
app.use((req, _res, next) => {
  const clientIp =
    (req.headers['x-forwarded-for'])?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(
    `[REQ] ${req.method} ${req.path} → ${clientIp} | ${_res.statusCode}`,
  );
  next();
});

// @note root endpoint
app.get('/', (_req, res) => {
  res.send('Hello, world!');
});

/**
 * @note dashboard endpoint - serves login HTML page with client data
 */
app.all('/player/login/dashboard', async (req, res) => {
  const body = req.body;
  let clientData = '';

  // @note body comes as { "key1|val1\nkey2|val2\n...": "" }
  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');

  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * @note validate login endpoint - validates GrowID credentials
 */
app.all('/player/growid/login/validate', async (req, res) => {
  try {
    const formData = req.body;
    const _token = formData._token;
    const growId = formData.growId;
    const password = formData.password;
    const email = formData.email;

    let token = '';
    if (email) {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=1`,
      ).toString('base64');
    } else {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&reg=0`,
      ).toString('base64');
    }

    res.send(
      JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
      }),
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * @note first checktoken endpoint - redirects using 307 to preserve data
 */
app.all('/player/growid/checktoken', async (req, res) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

/**
 * @note second checktoken endpoint - validates token and returns updated token
 */
app.all('/player/growid/validate/checktoken', async (req, res) => {
  try {
    let refreshToken;
    let clientData;

    const contentType = req.headers['content-type'] || '';

    if (
      contentType.includes('application/json') ||
      (typeof req.body === 'object' &&
        req.body !== null &&
        'refreshToken' in req.body)
    ) {
      const formData = req.body;
      refreshToken = formData.refreshToken;
      clientData = formData.clientData;
      console.log(`[CHECKTOKEN] Parsed as JSON/Object`);
    } else if (
      typeof req.body === 'object' &&
      req.body !== null &&
      Object.keys(req.body).length > 0
    ) {
      const formData = req.body;
      refreshToken = formData.refreshToken;
      clientData = formData.clientData;
      console.log(`[CHECKTOKEN] Parsed as form-urlencoded`);
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      const params = new URLSearchParams(req.body);
      refreshToken = params.get('refreshToken') || undefined;
      clientData = params.get('clientData') || undefined;
      console.log(`[CHECKTOKEN] Parsed as string/URLSearchParams`);
    }

    if (!refreshToken || !clientData) {
      console.log(`[ERROR]: Missing refreshToken or clientData`);
      res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
      return;
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');

    if (decodedRefreshToken.includes('&reg=0')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=0', '');
    } else if (decodedRefreshToken.includes('&reg=1')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=1', '');
    }

    const token = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');

    res.send(
      `{"status":"success","message":"Token is valid.","token":"${token}","url":"","accountType":"growtopia"}`,
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

// @note only listen when running locally (not on Vercel)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`[SERVER] Running on http://localhost:${PORT}`);
  });
}

module.exports = app;
