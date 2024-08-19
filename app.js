require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./models/UserModel');

const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3001;
const csrfProtection = csurf();

const { body, validationResult } = require('express-validator');

// Apply security-related HTTP headers
app.use(helmet());

// Rate limiter to prevent brute-force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});


mongoose.connect(process.env.db_connection, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

//app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.set('view engine', 'ejs');
app.use(express.static('public'));


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(csrfProtection);

// Routes
app.get('/', (req, res) => {
    res.render('welcome');
});

app.get('/register', (req, res) => {
    res.render('register', { errors: [], success: '', csrfToken: req.csrfToken() });
});

app.get('/login', (req, res) => {
    res.render('login', { errors: [], success: '', csrfToken: req.csrfToken() });
});

app.post('/register', 
    limiter,
[
    body('username')
            .isLength({ min: 5 }).withMessage('Username must be at least 5 characters long')
            .isAlphanumeric().withMessage('Username must be alphanumeric')
            .custom(async (username) => {
                const existingUser = await User.findOne({ username });
                if (existingUser) {
                    throw new Error('Username already in use');
                }
                return true;
            }),
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
        ],
    
        async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            //return res.status(400).render('register', { errors: errors.array(), success: '' });
            return res.status(400).render('register', { errors: errors.array(), success: '', csrfToken: req.csrfToken() });
        }

        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            username,
            password: hashedPassword
        });

        await user.save();

        // Render the registration page with a success message
        //res.render('register', { errors: [], success: 'Registration successful! Redirecting to login...' });
        res.render('register', { errors: [], success: 'Registration successful! Redirecting to login...', csrfToken: req.csrfToken() });    
    }
);

app.post('/login', 
    limiter,
    [
        body('username')
            .notEmpty().withMessage('Username is required'),
        body('password')
            .notEmpty().withMessage('Password is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            //return res.status(400).render('login', { errors: errors.array() });
            return res.status(400).render('login', { errors: errors.array(), csrfToken: req.csrfToken() });

        }

        const { username, password } = req.body;

        const user = await User.findOne({ username });

        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user._id;
            req.session.username = user.username;

            return res.redirect('/dashboard');
        }

        console.log("Invalid Login details");
        //return res.status(401).render('login', { errors: [{ msg: 'Invalid username or password' }] });
        return res.status(401).render('login', { errors: [{ msg: 'Invalid username or password' }], csrfToken: req.csrfToken() });

    }
);


app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('dashboard', {
        username: req.session.username
    })
});

const server = app.listen(port, () => {
    console.log("Server listening");
    mongoose.connect(process.env.db_connection).then(() => {
        console.log("Database Connected");
    });
});