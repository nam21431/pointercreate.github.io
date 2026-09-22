const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware to handle JSON and Form submissions
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve the HTML file from the current directory
app.use(express.static(__dirname));

// Initialize Database Storage Account
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) return console.error('Database connection failed:', err.message);
    console.log('Connected to the SQLite database storage.');
});

// Create Users Table
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`);

// 1. SIGN-UP ROUTE
app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send("Please fill in all fields.");
    }

    try {
        // Hash password before saving to the database for safety
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const sql = `INSERT INTO users (email, password) VALUES (?, ?)`;
        db.run(sql, [email, hashedPassword], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).send("An account with this email already exists.");
                }
                return res.status(500).send("Database storage failed.");
            }
            res.send("<h1>Sign-Up Successful!</h1><p>You can now go back and log in.</p>");
        });
    } catch (error) {
        res.status(500).send("Internal server error.");
    }
});

// 2. LOGIN ROUTE
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send("Please fill in all fields.");
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err) return res.status(500).send("Database error.");
        if (!user) return res.status(400).send("User account not found.");

        // Check if entered password matches the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send("Incorrect password credentials.");

        res.send(`<h1>Welcome back!</h1><p>Logged in successfully as: ${user.email}</p>`);
    });
});

// Start backend server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
