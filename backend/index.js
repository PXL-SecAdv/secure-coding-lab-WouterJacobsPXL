const pg = require('pg');

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

require('dotenv').config({ path: '../.env' });


const { isBcryptHash } = require('./utils/hashUtils');

const app = express();
const cors = require('cors')

const port = parseInt(process.env.PORT);

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS);

const pool = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT),
    connectionTimeoutMillis: 5000
});

// check and update unhashed passwords
async function upgradePlaintextPasswords() {
    try {
        const result = await pool.query('SELECT id, password FROM users');
        const users = result.rows;

        const updates = [];

        for (const user of users) {
            if (!isBcryptHash(user.password)) {
                console.log(`User ID ${user.id} has plaintext password. Rehashing...`);
                const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
                updates.push({ id: user.id, password: hashedPassword });
            }
        }

        for (const u of updates) {
            await pool.query('UPDATE users SET password = $1 WHERE id = $2', [u.password, u.id]);
            console.log(`Updated password for user ID ${u.id}`);
        }

        console.log(`Password upgrade complete: ${updates.length} user(s) updated.`);
    } catch (err) {
        console.error('Error upgrading passwords:', err);
        process.exit(1); // Stop app if DB fails
    }
}


console.log("Connecting...:")

app.use(cors({
    origin: 'http://localhost:8080',
    credentials: true
}));

app.use(bodyParser.json());

app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

app.get('/authenticate/:username/:password', async (request, response) => {
    const username = request.params.username;
    const password = request.params.password;

    // Check for SQL injection met regex
    const sqlInjectionPattern = /['";\\=#$%^&*+<>()]/;
    if (sqlInjectionPattern.test(username) || sqlInjectionPattern.test(password)) {
        console.log(`Authentication attempt for user: ${username} : possible SQL Injection Attack`);
        return response.status(403).json({ error: 'Invalid input characters detected' });
    }

    // length validation
    if (username.length > 50 || password.length > 100) {
        console.log(`Authentication attempt for user: ${username} : Input is too long`);
        return response.status(403).json({ error: 'Input exceeds maximum allowed length' });
    }

    try {
        // Create a new client for the session from the pool
        const client = await pool.connect();

        try {
            // Gebruik van parameterized query
            const query = 'SELECT user_name, password FROM users WHERE user_name=$1';
            const results = await client.query(query, [username]);

            // If the user is found, compare the plaintext password with the hashed password
            if (results.rows.length > 0) {
                const hashedPassword = results.rows[0].password;

                // vergelijk password met stored hash
                const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

                if (isPasswordCorrect) {
                    console.log(`Authentication attempt for user: ${username} - Success: true`);
                    response.status(200).json({ username: results.rows[0].user_name });
                } else {
                    console.log(`Authentication attempt for user: ${username} - Success: failed`);
                    response.status(401).json({ error: 'Authentication failed' });
                }
            } else {
                console.log(`Authentication attempt for user: ${username} - Success: failed`);
                response.status(401).json({ error: 'Authentication failed' });
            }
        } finally {
            // Release client back to pool
            client.release();
        }
    } catch (error) {
        console.error('Authentication error:', error);
        // Generic error message to avoid leaking information (OWASP 10: Improper Error Handling)
        response.status(500).json({ error: 'Authentication failed' });
    }
});

upgradePlaintextPasswords().then(() => {
app.listen(port, () => {
  console.log(`App running on port ${port}.`)
});
});

