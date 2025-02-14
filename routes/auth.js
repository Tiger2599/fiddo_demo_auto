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

// Relying Party information
const rpName = "Test App";
const rpID = "redesigned-memory-4x4rqw9w474cqwqj-3000.app.github.dev";
const origin = `https://${rpID}`;

// Helper function to convert Base64URL to Buffer
const base64urlToBuffer = (base64url) => {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(base64 + padding, 'base64');
};

// Helper function to convert Buffer to Base64URL
const bufferToBase64url = (buffer) => buffer.toString('base64url');

// Registration Page
router.get('/register', (req, res) => {
    res.render('register');
});

// Generate Registration Options
router.get('/generate-registration-options', async (req, res) => {
    const userID = uuidv4();
    const registrationOptions = await generateRegistrationOptions({
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

    console.log("register generate------------------",registrationOptions);


    // Convert challenge and user.id to Base64URL
    registrationOptions.challenge = bufferToBase64url(Buffer.from(registrationOptions.challenge));
    registrationOptions.user.id = bufferToBase64url(Buffer.from(registrationOptions.user.id));

    // Store challenge and userID in session
    req.session.challenge = registrationOptions.challenge;
    req.session.userID = userID;

    res.json(registrationOptions);
});

// Verify Registration Response
router.post('/verify-registration', async (req, res) => {
    const { body: response } = req;
    const { challenge, userID } = req.session;

    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        console.log("register verify------------------",verification);
        

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

            // Store the credential in memory
            credentials[userID] = {
                credentialID: (credentialID),
                credentialPublicKey: (credentialPublicKey),
                counter,
            };

            res.json({ success: true, msg: 'Registration successful!' });
        } else {
            res.json({ success: false, msg: 'Registration failed.' });
        }
    } catch (err) {
        console.error('Error during registration verification:', err);
        res.status(500).json({ success: false, msg: 'Internal server error.', error: err.message });
    }
});

// Login Page
router.get('/login', (req, res) => {
    res.render('login');
});

// Generate Authentication Options
router.get('/generate-login-options', async (req, res) => {
    try {
        const authOptions = await generateAuthenticationOptions({
            rpID,
            allowCredentials: Object.values(credentials).map((cred) => ({
                id: cred.credentialID,
                type: 'public-key',
            })),
            userVerification: 'preferred',
        });

        console.log("login generate-------------",authOptions);
        

        // Convert challenge to Base64URL
        authOptions.challenge = bufferToBase64url(Buffer.from(authOptions.challenge));

        // Store challenge in session
        req.session.challenge = authOptions.challenge;

        res.json(authOptions);
    } catch (err) {
        console.error('Error generating authentication options:', err);
        res.status(500).json({ success: false, msg: 'Failed to generate login options.', error: err.message });
    }
});

// Verify Authentication Response
router.post('/verify-login', async (req, res) => {
    try {
        const { body: response } = req;
        const { challenge, userID } = req.session;

        // Ensure the received response has Base64URL-decoded fields converted to Buffers
        response.rawId = (response.rawId);
        response.response.authenticatorData = (response.response.authenticatorData);
        response.response.clientDataJSON = (response.response.clientDataJSON);
        response.response.signature = (response.response.signature);
        if (response.response.userHandle) {
            response.response.userHandle = (response.response.userHandle);
        }

        // Retrieve and properly decode the stored credential
        const storedCredential = credentials[userID];
        const authenticator = {
            credentialID: (storedCredential.credentialID), // Decode from Base64URL to Buffer
            credentialPublicKey: (storedCredential.credentialPublicKey), // Decode from Base64URL to Buffer
            counter: storedCredential.counter,
        };
        
        console.log("verification",{
            response,
            expectedChallenge: challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator,
        });

        // Verify the authentication response
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge: challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator,
        });

        console.log(verification);

        if (verification.verified) {
            // Update counter in the stored credential
            storedCredential.counter = verification.authenticationInfo.newCounter;

            res.json({ success: true, msg: 'Login successful!' });
        } else {
            res.json({ success: false, msg: 'Login failed.' });
        }
    } catch (err) {
        console.error('Error during login verification:', err);
        res.status(500).json({ success: false, msg: 'Internal server error.', error: err.message });
    }
});


module.exports = router;
