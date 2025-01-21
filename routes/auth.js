const express = require('express');
const { v4: uuidv4 } = require('uuid');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const router = express.Router();

// In-memory "database"
const users = {};
const credentials = {};

let rpName = "Test";
let rpID = "";
let origin = "https://";

// Registration Page
router.get('/register', (req, res) => {
    res.render('register');
});

// Generate Registration Options
router.get('/generate-registration-options', (req, res) => {
    const userID = uuidv4();
    const registrationOptions = generateRegistrationOptions({
        rpName,
        rpID,
        userID,
        userName: `user-${userID}`,
        attestationType: 'direct',
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
        },
    });

    // Store challenge and userID in session
    req.session.challenge = registrationOptions.challenge;
    req.session.userID = userID;

    res.json(registrationOptions);
});

// Verify Registration Response
router.post('/verify-registration', async (req, res) => {
    const { body: response } = req;
    const { challenge, userID } = req.session;

    const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
    });

    if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

        // Store the credential in memory
        credentials[userID] = {
            credentialID: Buffer.from(credentialID).toString('base64'),
            credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64'),
            counter,
        };

        res.json({ success: true, msg: 'Registration successful!' });
    } else {
        res.json({ success: false, msg: 'Registration failed.' });
    }
});

// Login Page
router.get('/login', (req, res) => {
    res.render('login');
});

// Generate Authentication Options
router.get('/generate-auth-options', (req, res) => {
    const authOptions = generateAuthenticationOptions({
        rpID,
        allowCredentials: Object.values(credentials).map((cred) => ({
            id: Buffer.from(cred.credentialID, 'base64'),
            type: 'public-key',
        })),
        userVerification: 'preferred',
    });

    // Store challenge in session
    req.session.challenge = authOptions.challenge;

    res.json(authOptions);
});

// Verify Authentication Response
router.post('/verify-authentication', async (req, res) => {
    const { body: response } = req;
    const { challenge } = req.session;

    const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: credentials[req.session.userID], // Get authenticator info by userID
    });

    if (verification.verified) {
        res.json({ success: true, msg: 'Login successful!' });
    } else {
        res.json({ success: false, msg: 'Login failed.' });
    }
});

module.exports = router;
