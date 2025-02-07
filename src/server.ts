import express from 'express';
import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import colors from 'colors';

const app = express();
const port = 8080;
app.use(bodyParser.urlencoded({ extended: true }));

const CLIENT_ID = 'upfirst';
const REDIRECT_URI = 'http://localhost:8081/process';
const JWT_SECRET = 'your_secret_key';
const TOKEN_EXPIRED = 3600;

const authCodes: Record<string, string> = {};
const refreshTokens: Set<string> = new Set();

app.get('/api/oauth/authorize', (req, res) => {
    const { response_type, client_id, redirect_uri, state } = req.query;
    
    if (response_type !== 'code' || client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send('Invalid request');
    }
    
    const code = randomBytes(16).toString('hex');
    authCodes[code] = client_id;
    
    let redirectURL = `${redirect_uri}?code=${code}`;
    if (state) {
        redirectURL += `&state=${state}`;
    }
    
    res.redirect(redirectURL);
});

app.post('/api/oauth/token', (req, res) => {
    const { grant_type, code, client_id, redirect_uri } = req.body;
    
    if (grant_type === 'authorization_code') {
        if (!authCodes[code] || client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
            return res.status(400).json({ error: 'invalid_grant' });
        }
        
        delete authCodes[code];
        const accessToken = jwt.sign({ client_id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRED });
        const refreshToken = randomBytes(32).toString('hex');
        refreshTokens.add(refreshToken);
        
        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: TOKEN_EXPIRED,
            refresh_token: refreshToken,
        });
    }
    
    res.status(400).json({ error: 'unsupported_grant_type' });
});

app.listen(port, () => {
    console.log(colors.bgBlue(`OAuth 2.0 server is running on http://localhost:${port}`));
});