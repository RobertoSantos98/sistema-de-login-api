const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const pool = new Pool({
    user: 'admintest',
    host: 'localhost',
    database: 'apiteste',
    password: 'admin123',
    port: 5432,
});

const SECRET_KEY = 'your_jwt_secret_key';

// Função para criar um token JWT
function generateToken(user) {
    return jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
}

// Endpoint para registrar um novo usuário
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
            [email, hashedPassword]
        );
        const user = result.rows[0];
        res.status(201).json({ id: user.id, email: user.email });
        console.log(`Um usuario foi adicionado. Com login: ${user.email}`)
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Endpoint para autenticar um usuário
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password_hash)) {
            const token = generateToken(user);
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Credenciais Invalidas' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
