require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors'); // Importing cors
const path = require('path');

const app = express();

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
app.use(cors({
    origin: 'http://localhost:3001', // Update to your frontend URL if different
    credentials: true,
}));

// CSP Header Update 
app.use((req, res, next) => { 
    res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self' http://localhost:3000"); 
    next(); 
});

app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Mongoose connected'))
  .catch(err => console.error('Mongoose connection error:', err));

// Models
const tokenSchema = new mongoose.Schema({
    email: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 360000 }, // 1-hour expiry
});
const Token = mongoose.model('Token', tokenSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetKey: String,
    resetExpires: Date,
    invalidLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: Date,
    lastLoginTime: Date,
});
const User = mongoose.model('User', userSchema);

// Utility Functions
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
}

function isValidPassword(password) {
    const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    return regex.test(password);
}

// Set SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendResetEmail(email, resetKey) {
    //const resetUrl = `/reset-password?token=${resetKey}`;
    const msg = {
        to: email,
        from: 'sadcatjanine99@gmail.com',
        subject: 'Password Reset Request',
        html: `
            <p>You requested a password reset.</p>
            <p>Here is your reset token:</p>
            <p><strong>${resetKey}</strong></p>
        `,
    };

    try {
        await sgMail.send(msg);
        console.log('Password reset email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error.message);
        throw error; // Rethrow the error to be caught in the route handler
    }
}

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000, // 30 minutes
    },
}));

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.redirect('/login.html'); // Redirect to login if not authenticated
    }
}

// Rate Limiter
const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: 'Too many attempts. Please try again later.',
});

// Routes
// Static HTML Pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));
app.get('/404', (req, res) => res.sendFile(path.join(__dirname, 'public', '404.html')));

// API Routes
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!validator.isEmail(email) || !isValidPassword(password)) {
        return res.status(400).json({ success: true, message: 'Invalid email or password format.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await new User({ email, password: hashedPassword }).save();
        res.status(200).json({ success: true, message: 'Account created successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error creating account.' });
    }
});

app.post('/login', rateLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || (user.accountLockedUntil && user.accountLockedUntil > new Date())) {
            return res.status(403).json({ message: 'Account is locked or invalid credentials.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            user.invalidLoginAttempts += 1;
            if (user.invalidLoginAttempts >= 3) {
                user.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
                user.invalidLoginAttempts = 0;
            }
            await user.save();
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        user.invalidLoginAttempts = 0;
        user.accountLockedUntil = null;
        user.lastLoginTime = new Date();
        await user.save();

        req.session.userId = user._id;
        res.status(200).json({
            message: 'Login successful.',
            redirectUrl: 'dashboard.html',
        });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in.' });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format.' });

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Email not registered.' });

        const resetKey = generateRandomString(32);
        user.resetKey = resetKey;
        user.resetExpires = new Date(Date.now() + 360000 * 1000); // 1-hour expiry
        await user.save();

        await sendResetEmail(email, resetKey);
        res.status(200).json({ message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Error processing request:', error.message); // Log the specific error
        res.status(500).json({ message: 'Error processing request.', error: error.message });
    }
});

app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;
    if (!isValidPassword(newPassword)) {
        return res.status(400).json({ message: 'Password does not meet complexity requirements.' });
    }

    try {
        const user = await User.findOne({ resetKey });
        if (!user) return res.status(400).json({ message: 'Invalid or expired reset key.' });

        const new_Password = bcrypt.hash(newPassword)
        
        await User.updateOne(
            {_id: user._id},
            {$set: {password: new_Password, resetToken: null, resetExpirese: null}}
        )

        res.status(200).json({ success: true, message: 'Password reset successfully.' });
    } catch (error) {
        res.status(500).json({success: false, message: 'Error resetting password.' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ message: 'Logout failed.' });
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Handle 404 for other routes
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
