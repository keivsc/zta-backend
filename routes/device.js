import express from 'express';
import Database from '../src/db.js';
import { randomUUID, randomBytes } from 'crypto';
import Logger from '../src/logging.js';
import {UAParser} from 'ua-parser-js';
import {getClientIp, randomString, requireDebugAuth} from '../src/utils.js';
import * as ed from '@noble/ed25519';
import { getAllSessions } from '../services/session.js';

const router = express.Router();
const logger = new Logger('device');

// Database init
const deviceDb = new Database('devices.db');


await deviceDb.run(`
  CREATE TABLE IF NOT EXISTS devices (
    deviceId TEXT PRIMARY KEY,
    publicKey TEXT,
    createdAt INTEGER,
    lastUsed INTEGER
  )
`);

await deviceDb.run(`
CREATE TABLE IF NOT EXISTS challenges (
    challengeId TEXT PRIMARY KEY,
    deviceId TEXT,
    challenge TEXT,
    expiresAt INTEGER
)
`)




router.use((req, res, next)=>{

    const ua = req.get('User-Agent');
    const lang = req.get('Accept-Language');

    if (!ua || !lang) {
        return res.status(400).json({ error: 'Missing headers.' });
    }
    next();
});


router.post('/register', async(req, res)=>{
    const {publicKey} = req.body;
    let deviceId = req.cookies['x-device-id'] || '';

    if (!publicKey){
        return res.status(400).json({error:"Missing/mismatch body."})
    }
    const uaResult = UAParser(req.headers['user-agent']);
    const deviceType = uaResult.device.type || 'Desktop';
    const browser = uaResult.browser.name || 'UnknownBrowser';

    const userExists = await deviceDb.get(
        `SELECT createdAt, lastUsed FROM devices WHERE deviceId = ? LIMIT 1`,
        [deviceId]
    )

    if (!userExists){
        deviceId = `${deviceType}-${browser}-${randomString()}`;

        await deviceDb.run(
        `INSERT INTO devices (deviceId, publicKey, createdAt, lastUsed)
        VALUES (?, ?, ?, ?)`,
        [deviceId, publicKey, Date.now(), 0]
        );
    }else{
        if (userExists.createdAt < (Date.now() + 30 * 24 * 3600000)){
            await deviceDb.run(
                `DELETE FROM devices WHERE deviceId = ?`,
                [deviceId]
            )
            deviceId = `${deviceType}-${browser}-${randomString()}`;

            await deviceDb.run(
            `INSERT INTO devices (deviceId, publicKey, createdAt)
            VALUES (?, ?, ?)`,
            [deviceId, publicKey, Date.now()]
            );
        }   
    }

    const userChallenge = await deviceDb.get(
        `SELECT * FROM challenges WHERE deviceId = ?`,
        [deviceId]
    );

    let challengeId = null;
    let unsignedChallenge = null;
    let expiresAt = null;

    if(!userChallenge){
        challengeId = randomUUID();
        unsignedChallenge = randomBytes(32).toString('hex');
        expiresAt = Date.now() + 30000;
        await deviceDb.run(
            `INSERT INTO challenges VALUES (?, ?, ?, ?)`,
            [challengeId, deviceId, unsignedChallenge, expiresAt]
        );
    }else{
        challengeId = userChallenge.challengeId;
        unsignedChallenge = userChallenge.challenge;
        expiresAt = userChallenge.expiresAt;
    }

    return res.status(200).json({challengeId, challenge:unsignedChallenge, expiresAt});

});


router.post('/verify', async(req, res)=>{
    try{


    const {challengeId, signedChallenge} = req.body;
    let deviceId = req.cookies['x-device-id'] || '';
    if (!challengeId || typeof signedChallenge !== 'string') {
        return res.status(400).json({ error: "Missing/mismatch body." });
    }

    const userChallenges = await deviceDb.get(
        `SELECT challenge, expiresAt from challenges WHERE challengeId = ?`,
        [challengeId]
    );

    if (!userChallenges) {
        return res.status(401).json({ error: "Invalid challenge." });
    }
    if (userChallenges.expiresAt < Date.now()) {
        await deviceDb.run(
            `DELETE FROM challenges WHERE challengeId = ?`,
            [challengeId]
        );
        return res.status(401).json({ error: "Expired challenge." });
    }

    const userDevice = await deviceDb.get(
        `SELECT deviceId, publicKey from devices WHERE deviceId = (SELECT deviceId FROM challenges WHERE challengeId = ?)`,
        [challengeId]
    );

    if (!userDevice){
        return res.status(401).json({error:"Invalid device."})
    }

    deviceId = userDevice.deviceId;

    const publicKeyBytes = Uint8Array.from(Buffer.from(userDevice.publicKey, "base64"));
    const challengeBytes = Uint8Array.from(Buffer.from(userChallenges.challenge, "base64"));
    const signatureBytes = Uint8Array.from(Buffer.from(signedChallenge, "base64"));


    const validSignature = await ed.verifyAsync(signatureBytes, challengeBytes, publicKeyBytes);
    if (!validSignature){
        return res.status(401).json({error:"Invalid signature."});
    }

    await deviceDb.run(
        `UPDATE devices SET lastUsed = ? WHERE deviceId =?`,
        [Date.now(), deviceId]
    );

    await deviceDb.run(
        `DELETE FROM challenges WHERE challengeId = ?`,
        [challengeId]
    );

    res.cookie('x-device-id', deviceId, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: 60 * 60 * 1000
    });
    const ip = getClientIp(req);
    logger.info(`New Device Registered: ${deviceId}, IP: ${ip}`)
    return res.status(200).json({success: true, deviceId});
    }catch{
        return res.status(500).json({error:"Internal Server Error"})
    }
});

router.get('/check', async(req,res)=>{
    const deviceId = req.cookies['x-device-id'];
    if (!deviceId){
        return res.status(400).json({error:"Missing device id"});
    }
    const deviceCheck = await deviceDb.get(
        `SELECT publicKey, createdAt FROM devices WHERE deviceId = ?`,
        [deviceId]
    );
    if (!deviceCheck){
        return res.status(400).json({error:"Device ID does not exist"});
    }
    if (deviceCheck.createdAt > (Date.now() + 30 * 24 * 3600000)){
        await deviceDb.run(
            `DELETE FROM devices WHERE deviceId = ?`,
            [deviceId]
        )
        return res.status(400).json({error:"deviceId expired."})
    }   
    return res.status(200).json({success:true});
})



router.get('/all', requireDebugAuth, async (req, res) => {
  const rows = await getAllSessions();

  if (!rows.length) {
    return res.send('<h2>No sessions</h2>');
  }

  const headers = Object.keys(rows[0]);

  const table = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sessions Debug</title>
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont;
          background: #0f172a;
          color: #e5e7eb;
          padding: 20px;
        }
        table {
          border-collapse: collapse;
          width: 100%;
          background: #020617;
          border-radius: 8px;
          overflow: hidden;
        }
        th, td {
          padding: 10px 14px;
          text-align: left;
          border-bottom: 1px solid #1e293b;
          font-size: 14px;
        }
        th {
          background: #020617;
          color: #38bdf8;
          position: sticky;
          top: 0;
        }
        tr:hover {
          background: #020617;
        }
        td {
          white-space: nowrap;
        }
      </style>
    </head>
    <body>
      <h2>Sessions Table</h2>
      <table>
        <thead>
          <tr>
            ${headers.map(h => `<th>${h}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              ${headers.map(h => `<td>${r[h]}</td>`).join('')}
            </tr>
          `).join('')}
        </tbody>
      </table>
    </body>
    </html>
  `;

  return res.send(table);
});


export default router;