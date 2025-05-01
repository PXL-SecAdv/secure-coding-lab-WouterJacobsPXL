const pg = require('pg');

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors')

const port=3000;

const pool = new pg.Pool({
    user: 'secadv',
    host: 'db',
    database: 'pxldb',
    password: 'ilovesecurity',
    port: 5432,
    connectionTimeoutMillis: 5000
})

console.log("Connecting...:")

app.use(cors());
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
    const sqlInjectionPattern = /['";\\=\-#$%^&*+<>()]/;
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
            const query = 'SELECT user_name FROM users WHERE user_name=$1 AND password=$2';
            const results = await client.query(query, [username, password]);

            // Add request logging for security auditing
            console.log(`Authentication attempt for user: ${username} - Success: ${results.rows.length > 0}`);

            // Return only the username of the authenticated user
            if (results.rows.length > 0) {
                response.status(200).json({ username: results.rows[0].user_name });
            } else {
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

app.listen(port, () => {
  console.log(`App running on port ${port}.`)
})

