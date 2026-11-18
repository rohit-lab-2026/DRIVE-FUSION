import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { connectDB, isDbConnected, User } from './db.js';

// Express instance
const app = express();

// Render (and most hosts) terminate HTTPS in front of the app; trust the proxy
// so secure cookies and req.protocol work correctly.
app.set('trust proxy', 1);

// Middlewares
app.use(cors({
    origin: process.env.APP_ORIGIN || 'http://localhost:5173', // your Vite frontend
    credentials: true, // needed so the session cookie is sent/received
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: true,
    // 'auto' = secure cookie over HTTPS (Render), plain cookie on http://localhost
    cookie: { secure: 'auto', sameSite: 'lax', maxAge: 10 * 60 * 1000 },
}));

// Connect to MongoDB Atlas (accounts are stored there, see db.js)
connectDB();

function requireDb(req, res, next) {
    if (!isDbConnected()) {
        return res.status(503).json({
            message: 'Database is not connected right now. Please try again shortly.',
        });
    }
    next();
}

// Mail sender: Brevo transactional email REST API (free plan: 300 emails/day).
// It uses HTTPS (port 443), so it works on Render's free tier, which blocks SMTP ports.
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const MAIL_FROM_EMAIL = process.env.MAIL_FROM_EMAIL; // must be a verified sender in Brevo
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'DriveFusion';

async function sendMail({ to, subject, html }) {
    if (!BREVO_API_KEY || !MAIL_FROM_EMAIL) {
        throw new Error('BREVO_API_KEY and MAIL_FROM_EMAIL must be set.');
    }
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'api-key': BREVO_API_KEY,
            'content-type': 'application/json',
            accept: 'application/json',
        },
        body: JSON.stringify({
            sender: { name: MAIL_FROM_NAME, email: MAIL_FROM_EMAIL },
            to: [{ email: to }],
            subject,
            htmlContent: html,
        }),
        signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        throw new Error(`Brevo responded ${response.status}: ${detail}`);
    }
}

if (BREVO_API_KEY && MAIL_FROM_EMAIL) {
    console.log('[mail] Brevo configured, sending as', MAIL_FROM_EMAIL);
} else {
    console.error('[mail] config error: set BREVO_API_KEY and MAIL_FROM_EMAIL');
}

// Generates an OTP, remembers it in the visitor's session, and emails it.
// Shared by /api/send-otp, /api/register and /api/forgot-password.
async function issueOtp(req, email, purpose) {
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    req.session.otp = otp;
    req.session.otpEmail = email.toLowerCase();
    req.session.otpPurpose = purpose || 'verify';
    req.session.otpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    const subject = purpose === 'reset'
        ? 'DriveFusion password reset code'
        : 'Verify your DriveFusion email';
    const html = `
      <div style="font-family: sans-serif; max-width: 420px; margin: auto;">
        <h2>${subject}</h2>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">${otp}</p>
        <p style="color:#666; font-size: 13px;">This code expires in 10 minutes.</p>
      </div>
    `;

    await sendMail({ to: email, subject, html });
    return { message: 'OTP sent.' };
}

// Routes

app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend API is running smoothly!' });
});

// Create an account. Password is hashed before it ever touches the database;
// the account starts unverified until the OTP emailed here is confirmed.
app.post('/api/register', requireDb, async (req, res) => {
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        await User.create({ fullName, email: email.toLowerCase(), passwordHash, verified: false });

        const result = await issueOtp(req, email, 'verify');
        res.json({ message: result.message || `We sent a verification code to ${email}.` });
    } catch (err) {
        console.error('[register] error:', err.message);
        res.status(500).json({ message: 'Could not create the account.' });
    }
});

// Validate email + password against what's stored in MongoDB.
app.post('/api/login', requireDb, async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const passwordMatches = await bcrypt.compare(password, user.passwordHash);
        if (!passwordMatches) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        if (!user.verified) {
            const result = await issueOtp(req, email, 'verify');
            return res.json({
                message: result.message || 'Please verify your email before signing in. We sent a new code.',
            });
        }

        const token = crypto.randomBytes(24).toString('hex');
        res.json({ token, user: { fullName: user.fullName, email: user.email } });
    } catch (err) {
        console.error('[login] error:', err.message);
        res.status(500).json({ message: 'Login failed.' });
    }
});

// Ask the server to (re)send an OTP without creating an account — used for
// flows that only need a one-off code.
app.post('/api/send-otp', async (req, res) => {
    const { email, purpose } = req.body || {};
    if (!email) return res.status(400).json({ message: 'email is required.' });

    try {
        const result = await issueOtp(req, email, purpose);
        res.json(result);
    } catch (err) {
        console.error('[mail] send failed:', err.message);
        res.status(500).json({ message: 'Failed to send email.' });
    }
});

// Check the code the visitor typed against what's stored in their session.
// On success (and when called during signup) this also marks the account
// verified in MongoDB.
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body || {};

    if (!req.session.otp) {
        return res.status(400).json({ message: 'No code was requested.' });
    }
    if (Date.now() > req.session.otpExpiresAt) {
        return res.status(400).json({ message: 'Code expired. Request a new one.' });
    }
    if (req.session.otpEmail !== (email || '').toLowerCase() || req.session.otp !== otp) {
        return res.status(400).json({ message: 'Incorrect code.' });
    }

    delete req.session.otp;
    delete req.session.otpEmail;
    delete req.session.otpExpiresAt;

    if (isDbConnected()) {
        try {
            await User.updateOne({ email: (email || '').toLowerCase() }, { verified: true });
        } catch (err) {
            console.error('[verify-otp] could not mark user verified:', err.message);
        }
    }

    res.json({ message: 'Verified.' });
});

// Start a password reset: confirms the account exists, then emails an OTP.
app.post('/api/forgot-password', requireDb, async (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: 'email is required.' });

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({ message: 'No account found with this email.' });
        }

        const result = await issueOtp(req, email, 'reset');
        res.json({ message: result.message || `We sent a password reset code to ${email}.` });
    } catch (err) {
        console.error('[forgot-password] error:', err.message);
        res.status(500).json({ message: 'Could not process the request.' });
    }
});

// Finish a password reset: checks the OTP against the session, then updates
// the stored password hash in MongoDB.
app.post('/api/reset-password', requireDb, async (req, res) => {
    const { email, otp, newPassword } = req.body || {};
    if (!email || !otp || !newPassword) {
        return res.status(400).json({ message: 'email, otp and newPassword are required.' });
    }

    if (!req.session.otp) {
        return res.status(400).json({ message: 'No code was requested.' });
    }
    if (Date.now() > req.session.otpExpiresAt) {
        return res.status(400).json({ message: 'Code expired. Request a new one.' });
    }
    if (req.session.otpEmail !== email.toLowerCase() || req.session.otp !== otp) {
        return res.status(400).json({ message: 'Incorrect code.' });
    }

    delete req.session.otp;
    delete req.session.otpEmail;
    delete req.session.otpExpiresAt;

    try {
        const passwordHash = await bcrypt.hash(newPassword, 10);
        const result = await User.updateOne({ email: email.toLowerCase() }, { passwordHash });
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'Account not found.' });
        }
        res.json({ message: 'Password reset successfully.' });
    } catch (err) {
        console.error('[reset-password] error:', err.message);
        res.status(500).json({ message: 'Could not reset the password.' });
    }
});

// Serve the built React frontend (run `npm run build` in the project root first)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(__dirname, '..', 'dist');
app.use(express.static(distDir));
app.get('*', (req, res) => res.sendFile(path.join(distDir, 'index.html')));

// Start the server
const PORT = process.env.PORT || 4040;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
