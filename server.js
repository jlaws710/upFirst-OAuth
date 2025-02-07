"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = require("express");
var crypto_1 = require("crypto");
var jsonwebtoken_1 = require("jsonwebtoken");
var body_parser_1 = require("body-parser");
var app = (0, express_1.default)();
var port = 8080;
app.use(body_parser_1.default.urlencoded({ extended: true }));
var CLIENT_ID = 'upfirst';
var REDIRECT_URI = 'http://localhost:8081/process';
var JWT_SECRET = 'your_secret_key';
var TOKEN_EXPIRY = 3600;
var authCodes = {};
var refreshTokens = new Set();
app.get('/api/oauth/authorize', function (req, res) {
    var _a = req.query, response_type = _a.response_type, client_id = _a.client_id, redirect_uri = _a.redirect_uri, state = _a.state;
    if (response_type !== 'code' || client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send('Invalid request');
    }
    var code = (0, crypto_1.randomBytes)(16).toString('hex');
    authCodes[code] = client_id;
    var redirectURL = "".concat(redirect_uri, "?code=").concat(code);
    if (state) {
        redirectURL += "&state=".concat(state);
    }
    res.redirect(redirectURL);
});
app.post('/api/oauth/token', function (req, res) {
    var _a = req.body, grant_type = _a.grant_type, code = _a.code, client_id = _a.client_id, redirect_uri = _a.redirect_uri;
    if (grant_type === 'authorization_code') {
        if (!authCodes[code] || client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
            return res.status(400).json({ error: 'invalid_grant' });
        }
        delete authCodes[code];
        var accessToken = jsonwebtoken_1.default.sign({ client_id: client_id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
        var refreshToken = (0, crypto_1.randomBytes)(32).toString('hex');
        refreshTokens.add(refreshToken);
        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: TOKEN_EXPIRY,
            refresh_token: refreshToken,
        });
    }
    res.status(400).json({ error: 'unsupported_grant_type' });
});
app.listen(port, function () {
    console.log("OAuth 2.0 server running on http://localhost:".concat(port));
});
