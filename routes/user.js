import express from 'express';
import dotenv from 'dotenv';
import Logger from '../src/logging.js';
import { createAccount, deleteAccount, getAll, getUsernameById, login, searchUsers, verifyTotp } from '../services/user.js';
import { generateToken, verifyToken } from '../services/session.js';
import { verifyChallengeAndIssueToken } from '../services/user.js';
import { getClientIp, requireDebugAuth, requireSession } from '../src/utils.js';

dotenv.config({ quiet: true });
const router = express.Router();
const logger = new Logger('user');

router.use((req, res, next) => {
    if (req.path === '/all') {
        return next();
    }
    const deviceId = req.cookies['x-device-id'];
    if (!deviceId) return res.status(400).json({ error: "Missing device id." });
    next();
});

router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: "Missing username, email or password." });
        const { userId, otpauthURL } = await createAccount({ username, email, password });
        logger.info(`New user registered: ${email}`);
        res.status(200).json({ success: true, otpauthURL });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password, signPublic, encryptPublic } = req.body;
        const deviceId = req.cookies['x-device-id'];
        const result = await login({ email, password, deviceId, signPublic, encryptPublic });
        res.status(200).json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/totp', async (req, res) => {
    try {
        const { totp, userId } = req.body;
        const deviceId = req.cookies['x-device-id'];
        const valid = await verifyTotp({ deviceId, userId, token: totp });
        if (!valid) return res.status(400).json({ error: "Invalid TOTP code." });

        const sessionToken = await generateToken(
            userId,
            deviceId,
            getClientIp(req)
        );

        res.cookie('session', sessionToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 3600 * 1000 });
        res.status(200).json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});




router.get('/name', requireSession, async(req, res)=>{
    const username = await getUsernameById(result.userId);
    return res.status(200).json({ username });
})

router.get('/name/:userId', async (req, res) => {
    const { userId } = req.params;
    const username = await getUsernameById(userId);
    if (!username) {
        return res.status(404).json({ error: "User not found." });
    }
    return res.status(200).json({ username });
});

router.post('/verify', async (req, res) => {
    try {
        const { signature, nonce } = req.body;
        const deviceId = req.cookies['x-device-id'];
        const ip = getClientIp(req);
        const result = await verifyChallengeAndIssueToken({
            deviceId,
            signature,
            nonce,
            ip: ip
        });

        if (result.totpRequired) {
            return res.status(401).json({
                error: "TOTP required.",
                userId: result.userId,
                expiresAt: result.expiresAt
            });
        }

        res.cookie('session', result.sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 60 * 60 * 1000
        });

        return res.status(200).json({ success: true });

    } catch (err) {

        return res.status(400).json({ error: err.message });
    }
});

router.post('/session', async (req, res) => {
    const token = req.cookies['session'];
    const deviceId = req.cookies['x-device-id'];

    if (!deviceId || !token) {
        return res.status(400).json({ error: "Missing device id." });
    }

    const result = await verifyToken(token, deviceId, getClientIp(req));

    if (result.action === "DENY") {
        return res.status(401).json({ error: "Invalid session" });
    }

    if (result.action === "STEP_UP") {
        return res.status(401).json({ error: "Step-up authentication required" });
    }

    return res.status(200).json({ success: true });

});


router.get('/search/:query', requireSession, async (req, res) => {
    try {
        const query = req.params.query;
        if (!query) {
            return res.status(400).json({ error: "Missing search query." });
        }
        const results = await searchUsers(query);
        return res.status(200).json({ results });
    } catch (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

router.get('/all', requireDebugAuth, async(req, res) => {
    const { users, devices, challenges, totp } = await getAll();
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Auth Debug</title>
            <style>
                body {
                    font-family: system-ui;
                    background: #0f172a;
                    color: #e5e7eb;
                    padding: 20px;
                }
                h2 {
                    margin-top: 40px;
                    color: #38bdf8;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    background: #020617;
                    border-radius: 8px;
                    overflow: hidden;
                }
                th, td {
                    padding: 10px 14px;
                    border-bottom: 1px solid #1e293b;
                    text-align: left;
                    font-size: 14px;
                }
                th {
                    position: sticky;
                    top: 0;
                    background: #020617;
                }
            </style>
        </head>
        <body>
            <h1>Auth Debug Tables</h1>
            ${renderTable('Users', users)}
            ${renderTable('Device Keys', devices)}
            ${renderTable('Auth Challenges', challenges)}
            ${renderTable('TOTP', totp)}
        </body>
        </html>
    `);
});

function renderTable(title, rows) {
    if (!rows.length) return `<h2>${title}</h2><p>No data</p>`;
    const headers = Object.keys(rows[0]);
    return `
        <h2>${title}</h2>
        <table>
            <thead>
                <tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>
            </thead>
            <tbody>
                ${rows.map(r => `
                    <tr>${headers.map(h => `<td>${r[h]}</td>`).join('')}</tr>
                `).join('')}
            </tbody>
        </table>
    `;
}



export default router;