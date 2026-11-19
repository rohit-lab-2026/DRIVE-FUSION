import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cors from 'cors';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
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

// JWTs are signed with the same secret used for session cookies, so only one
// secret needs to be configured. Logged-in requests send the token back as
// "Authorization: Bearer <token>".
const JWT_SECRET = process.env.SESSION_SECRET || 'fallback-secret-key';

function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) {
        return res.status(401).json({ message: 'Missing or invalid Authorization header.' });
    }

    try {
        req.auth = jwt.verify(token, JWT_SECRET); // { email, iat, exp }
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token. Please log in again.' });
    }
}

// Guards admin-only routes (e.g. listing every user). Requires a secret
// header matching ADMIN_KEY on the server - set it in Render's Environment
// tab, never commit the real value. If ADMIN_KEY isn't configured at all,
// the route is locked out entirely rather than silently left open.
function requireAdmin(req, res, next) {
    const configuredKey = process.env.ADMIN_KEY;
    if (!configuredKey) {
        return res.status(503).json({ message: 'Admin access is not configured on this server.' });
    }
    const providedKey = req.headers['x-admin-key'];
    if (providedKey !== configuredKey) {
        return res.status(403).json({ message: 'Invalid admin key.' });
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

    const key = email.toLowerCase();
    let createdUser;

    // Step 1: save the account. Any failure here (duplicate email, bad data,
    // a DB hiccup) is a genuine "could not create the account" error.
    try {
        const existing = await User.findOne({ email: key });
        if (existing) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        createdUser = await User.create({ fullName, email: key, passwordHash, verified: false });
    } catch (err) {
        console.error('[register] could not save account:', err.message);
        return res.status(500).json({ message: 'Could not create the account.' });
    }

    // Step 2: send the verification email. If THIS fails (e.g. the Brevo
    // sender isn't verified, bad API key, Brevo is down), the account was
    // still created — so we roll it back instead of leaving an orphaned,
    // unverified account that would block every future registration attempt
    // with "already exists" while never being able to receive its OTP.
    try {
        const result = await issueOtp(req, email, 'verify');
        res.json({ message: result.message || `We sent a verification code to ${email}.` });
    } catch (err) {
        console.error('[register] account created but OTP email failed, rolling back:', err.message);
        await User.deleteOne({ _id: createdUser._id }).catch((cleanupErr) => {
            console.error('[register] rollback delete failed:', cleanupErr.message);
        });
        res.status(502).json({
            message: 'We could not send the verification email. Please check the mail configuration and try again.',
        });
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
            try {
                const result = await issueOtp(req, email, 'verify');
                return res.json({
                    message: result.message || 'Please verify your email before signing in. We sent a new code.',
                });
            } catch (otpErr) {
                console.error('[login] credentials ok but OTP email failed:', otpErr.message);
                return res.status(502).json({
                    message: 'Your password is correct, but your account is still unverified and we could not send a new code. Please try again shortly.',
                });
            }
        }

        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { fullName: user.fullName, email: user.email } });
    } catch (err) {
        console.error('[login] error:', err.message);
        res.status(500).json({ message: 'Login failed.' });
    }
});

// Returns the logged-in user's own account info. Requires a valid JWT from
// /api/login in the Authorization header — never returns the password hash.
app.get('/api/me', requireAuth, requireDb, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.auth.email });
        if (!user) {
            return res.status(404).json({ message: 'Account not found.' });
        }
        res.json({
            fullName: user.fullName,
            email: user.email,
            verified: user.verified,
            createdAt: user.createdAt,
        });
    } catch (err) {
        console.error('[me] error:', err.message);
        res.status(500).json({ message: 'Could not fetch account info.' });
    }
});

// Admin-only: list every registered account. Never returns password hashes.
// Requires the x-admin-key header to match ADMIN_KEY (see requireAdmin above).
app.get('/api/users', requireAdmin, requireDb, async (req, res) => {
    try {
        const users = await User.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).lean();
        res.json(users);
    } catch (err) {
        console.error('[users] error:', err.message);
        res.status(500).json({ message: 'Could not fetch users.' });
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
