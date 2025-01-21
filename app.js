const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();

// Middleware
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
}));

// Set EJS
app.set('view engine', 'ejs');

// Routes
app.use('/auth', authRoutes);

// Default Route
app.get('/', (req, res) => res.redirect('/auth/login'));

// Start Server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
