import Database from '../src/db.js';
import Logger from '../src/logging.js';
import { randomBytes, createHmac } from 'crypto';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config({ quiet: true });

const logger = new Logger('session');
const sesDb = new Database("session.db");

/* =========================
   DATABASE INITIALIZATION
   ========================= */

await sesDb.run(`
CREATE TABLE IF NOT EXISTS sessions (
    userId TEXT PRIMARY KEY,
    deviceId TEXT,
    nonce TEXT,
    expiresAt INTEGER,
    trustScore INTEGER,
    token TEXT,
    IP TEXT,
    lastSeen INTEGER,
    ipChanges INTEGER,
    requestCount INTEGER
)`);

const HMAC_SECRET = Buffer.from(process.env.HMAC_SECRET, 'hex');
const JWT_SECRET  = Buffer.from(process.env.JWT_SECRET, 'hex');

/* =========================
   ADAPTIVE HELPERS
   ========================= */

function tokenLifetime(trustScore) {
    if (trustScore >= 90) return '2h';
    if (trustScore >= 80) return '1h';
    if (trustScore >= 70) return '15m';
    return '5m';
}

function calculateRisk(session, currentIp) {
    let risk = 0;

    if (session.IP !== currentIp) risk += 20;
    if (session.ipChanges > 2) risk += 10;

    const idleTime = Date.now() - session.lastSeen;
    if (idleTime >= 30 * 60 * 1000) risk += 10;

    if (session.requestCount >= 499) risk += 20;

    return risk;
}

/* =========================
   TOKEN GENERATION
   ========================= */

export async function generateToken(userId, deviceId, ip) {
    const nonce = randomBytes(16).toString('hex');

    const payload = { userId, deviceId, nonce };
    const hmac = createHmac('sha256', HMAC_SECRET)
        .update(JSON.stringify(payload))
        .digest('hex');

    const trustScore = 100;

    const token = jwt.sign(
        { payload, hmac },
        JWT_SECRET,
        { expiresIn: tokenLifetime(trustScore) }
    );

    await sesDb.run(`DELETE FROM sessions WHERE userId = ?`, [userId]);

    await sesDb.run(`
        INSERT INTO sessions
        (userId, deviceId, nonce, expiresAt, trustScore, token, IP, lastSeen, ipChanges, requestCount)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        userId,
        deviceId,
        nonce,
        Date.now() + 3600000,
        trustScore,
        token,
        ip,
        Date.now(),
        0,
        0
    ]);

    return token;
}

/* =========================
   CONTINUOUS VERIFICATION
   ========================= */

export async function verifyToken(token, deviceId, currentIp) {
    try {
        const session = await sesDb.get(
            `SELECT * FROM sessions WHERE token = ?`,
            [token]
        );

        if (!session || session.deviceId !== deviceId) {
            throw new Error();
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        const expectedHmac = createHmac('sha256', HMAC_SECRET)
            .update(JSON.stringify(decoded.payload))
            .digest('hex');

        if (decoded.hmac !== expectedHmac) throw new Error();
        if (decoded.payload.userId !== session.userId) throw new Error();

        let trustScore = session.trustScore;
        const risk = calculateRisk(session, currentIp);

        trustScore = Math.max(0, trustScore - risk);

        if (risk === 0) {
            trustScore = Math.min(100, trustScore + 1);
        }

        const ipChanged = session.IP !== currentIp ? 1 : 0;

        await sesDb.run(`
            UPDATE sessions SET
                trustScore = ?,
                IP = ?,
                lastSeen = ?,
                ipChanges = ipChanges + ?,
                requestCount = requestCount + 1
            WHERE token = ?
        `, [
            trustScore,
            currentIp,
            Date.now(),
            ipChanged,
            token
        ]);

        if (trustScore <= 60) {
            await sesDb.run(`DELETE FROM sessions WHERE token = ?`, [token]);
            return { action: "DENY" };
        }

        if (trustScore <= 80) {
            return { action: "STEP_UP", userId: session.userId };
        }

        return { action: "ALLOW", userId: session.userId };

    } catch {
        await sesDb.run(`DELETE FROM sessions WHERE token = ?`, [token]);
        return { action: "DENY" };
    }
}

/* =========================
   TRUST SCORE ADJUSTMENT
   ========================= */

export async function updateTrustScore(token, delta) {
    await sesDb.run(`
        UPDATE sessions
        SET trustScore = MIN(100, MAX(0, trustScore + ?))
        WHERE token = ?
    `, [delta, token]);

    return true;
}

/* =========================
   ADMIN / DEBUG
   ========================= */

export async function getAllSessions() {
    return await sesDb.getAll(`SELECT * FROM sessions`);
}





export async function evaluateSession({ userId, deviceId, currentIp }) {
  try {
    const session = await sesDb.get(
      `SELECT * FROM sessions WHERE userId = ? AND deviceId = ?`,
      [userId, deviceId]
    );

    if (!session) {
      return { action: "DENY", userId, deviceId, currentIp };
    }

    let trustScore = session.trustScore;

    const risk = calculateRisk(session, currentIp);

    if (risk === 0) {
      trustScore = Math.min(100, trustScore + 1); // slight increase for safe usage
    }

    // Update session stats
    await sesDb.run(
      `UPDATE sessions SET
         trustScore = ?,
         IP = ?,
         lastSeen = ?,
         ipChanges = ipChanges + ?,
         requestCount = requestCount + 1
       WHERE userId = ? AND deviceId = ?`,
      [trustScore, currentIp, Date.now(), ipChanged ? 1 : 0, userId, deviceId]
    );

    if (trustScore < 60) {
      await sesDb.run(`DELETE FROM sessions WHERE userId = ? AND deviceId = ?`, [userId, deviceId]);
      return { action: "DENY", userId, deviceId, currentIp };
    }

    if (trustScore < 80) {
      return { action: "STEP_UP", userId, deviceId, currentIp };
    }

    return { action: "ALLOW", userId, deviceId, currentIp };

  } catch (err) {
    // On any error, deny access
    console.log(err);
    await sesDb.run(`DELETE FROM sessions WHERE userId = ? AND deviceId = ?`, [userId, deviceId]);
    return { action: "DENY", userId, deviceId, currentIp };
  }
}