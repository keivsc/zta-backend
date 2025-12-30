import Database from '../src/db.js';
import { randomBytes, createCipheriv, randomUUID, createDecipheriv } from 'crypto';
import { hashPassword } from '../src/crypto.js';
import speakeasy from 'speakeasy';
import dotenv from 'dotenv';
import { evaluateSession } from './session.js';

dotenv.config({ quiet: true });
const AES_SECRET = Buffer.from(process.env.AES_SECRET, 'hex');
const userDb = new Database('user.db');

await userDb.run(`
    CREATE TABLE IF NOT EXISTS users(
        userId TEXT PRIMARY KEY,
        username TEXT,
        email TEXT,
        passwordHash TEXT,
        passwordSalt TEXT,
        TOTPSecretEnc TEXT,
        TOTPiv TEXT,
        TOTPTag TEXT,
        loginAttempts INTEGER DEFAULT 0,
        lastLoginAttempt INTEGER
    )`);
await userDb.run(`
    CREATE TABLE IF NOT EXISTS deviceKeys(
        deviceId TEXT PRIMARY KEY,
        userId TEXT,
        signPublic TEXT,
        encryptPublic TEXT,
        totpCheck BOOLEAN,
        createdAt INTEGER,
        lastUsed INTEGER
    )`);
await userDb.run(`
    CREATE TABLE IF NOT EXISTS authChallenges(
        deviceId TEXT PRIMARY KEY,
        userId TEXT,
        challenge TEXT,
        nonce TEXT,
        expiresAt INTEGER
    )`);
await userDb.run(`
    CREATE TABLE IF NOT EXISTS totp(
        deviceId TEXT PRIMARY KEY,
        userId TEXT,
        expiresAt INTEGER
    )`);


// ✅ Create a new user account
export async function createAccount({ username, email, password }) {
    const emailExists = await userDb.get(`
        SELECT * FROM users WHERE email = ?`,
    [email])
    if (emailExists){
        throw new Error("Email already exists.")
    }
    const salt = randomBytes(32);
    const passwordHash = await hashPassword(password, salt);

    const totpSecret = speakeasy.generateSecret({ length: 20 });
    const iv = randomBytes(12);
    const totpCipher = createCipheriv("aes-256-gcm", AES_SECRET, iv);
    const encryptedTotp = Buffer.concat([
        totpCipher.update(totpSecret.base32, "utf8"),
        totpCipher.final()
    ]);
    const authTag = totpCipher.getAuthTag();

    const userId = randomUUID();

    await userDb.run(
        `INSERT INTO users (userId, username, email, passwordHash, passwordSalt, TOTPSecretEnc, TOTPiv, TOTPTag)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, username, email, passwordHash.hash, salt.toString('base64'), encryptedTotp.toString('base64'), iv.toString('base64'), authTag.toString('base64')]
    );

    return {
        userId,
        otpauthURL: speakeasy.otpauthURL({
            secret: totpSecret.base32,
            label: "ZTA Demo",
            issuer: "ZTA Demo",
            encoding: "base32",
            algorithm: "sha1"
        })
    };
}

// ✅ Delete a user account
export async function deleteAccount(userId) {
    await userDb.run(`DELETE FROM users WHERE userId = ?`, [userId]);
    await userDb.run(`DELETE FROM deviceKeys WHERE userId = ?`, [userId]);
    await userDb.run(`DELETE FROM authChallenges WHERE userId = ?`, [userId]);
    await userDb.run(`DELETE FROM totp WHERE userId = ?`, [userId]);
}

// ✅ Login user and manage device keys & challenges
export async function login({
    email,
    password,
    deviceId,
    signPublic,
    encryptPublic,
    maxLoginAttempts = 5,
    lockTime = 15 * 60 * 1000
}) {
    // Fetch user
    const user = await userDb.get(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) throw new Error("Email or password mismatch.");

    // Lockout check
    if (
        user.loginAttempts >= maxLoginAttempts &&
        user.lastLoginAttempt &&
        (Date.now() - user.lastLoginAttempt) < lockTime
    ) {
        throw new Error("Account locked. Try later.");
    }

    // Password verify
    const passwordHash = await hashPassword(password, Buffer.from(user.passwordSalt, "base64"));

    if (passwordHash.hash !== user.passwordHash) {
        await userDb.run(
            `UPDATE users SET loginAttempts = loginAttempts + 1, lastLoginAttempt = ? WHERE email = ?`,
            [Date.now(), email]
        );
        throw new Error("Email or password mismatch.");
    }

    // Reset attempts
    await userDb.run(
        `UPDATE users SET loginAttempts = 0, lastLoginAttempt = ? WHERE userId = ?`,
        [Date.now(), user.userId]
    );

    // Register device if not exists
    const existingDevice = await userDb.get(
        `SELECT deviceId FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );

    if (!existingDevice) {
        if (!signPublic || !encryptPublic) {
            throw new Error("Public key missing.");
        }

        await userDb.run(
            `INSERT INTO deviceKeys(deviceId, userId, signPublic, encryptPublic, totpCheck, createdAt, lastUsed)
             VALUES(?, ?, ?, ?, ?, ?, ?)`,
            [deviceId, user.userId, signPublic, encryptPublic, true, Date.now(), null]
        );
    }

    // 🔑 ALWAYS issue or reuse challenge
    const existingChallenge = await userDb.get(
    `SELECT challenge, nonce, expiresAt FROM authChallenges WHERE deviceId = ?`,
    [deviceId]
    );

    if (existingChallenge) {
    if (existingChallenge.expiresAt > Date.now()) {
        return {
        userId: user.userId,
        nonce: existingChallenge.nonce,
        challenge: existingChallenge.challenge
        };
    }

    // expired → clean it
    await userDb.run(
        `DELETE FROM authChallenges WHERE deviceId = ?`,
        [deviceId]
    );
    }


    const nonce = randomBytes(32).toString("base64");
    const challenge = randomBytes(16).toString("base64");
    const expiresAt = Date.now() + 30_000;

    await userDb.run(
        `INSERT INTO authChallenges(deviceId, userId, challenge, nonce, expiresAt)
         VALUES(?,?,?,?,?)`,
        [deviceId, user.userId, challenge, nonce, expiresAt]
    );

    return { userId: user.userId, nonce, challenge };
}


export async function verifyChallengeAndIssueToken({
    deviceId,
    signature,
    nonce,
    ip
}) {
    if (!signature || !nonce) {
        throw new Error("Missing signature or nonce.");
    }

    const deviceKeys = await userDb.get(
        `SELECT signPublic, TOTPCheck FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );

    if (!deviceKeys) {
        throw new Error("Invalid device.");
    }

    const { signPublic, TOTPCheck } = deviceKeys;

    const challengeCheck = await userDb.get(
        `SELECT userId, challenge, nonce, expiresAt
         FROM authChallenges WHERE deviceId = ?`,
        [deviceId]
    );

    if (!challengeCheck) {
        throw new Error("Invalid challenge.");
    }

    const { userId, challenge, nonce: realNonce, expiresAt } = challengeCheck;

    if (expiresAt < Date.now()) {
        await userDb.run(`DELETE FROM authChallenges WHERE deviceId = ?`, [deviceId]);
        throw new Error("Challenge expired.");
    }

    if (nonce !== realNonce) {
        throw new Error("Invalid verification.");
    }

    try {
    const publicKey = await crypto.subtle.importKey(
        'spki',
        Buffer.from(signPublic, 'base64'),
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify']
    );

    const validSignature = await crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        publicKey,
        Buffer.from(signature, 'base64'),
        Buffer.from(challenge, 'base64')
    );

    if (!validSignature) {
        throw new Error("Invalid signature.");
    }
    } catch(err) {
        throw new Error("Verification error.");
    }

    await userDb.run(
    `DELETE FROM authChallenges WHERE deviceId = ?`,
    [deviceId]
    );

    const sessionToken = await evaluateSession({ userId, deviceId, ip });

    console.log(sessionToken)
    console.log(TOTPCheck)

    if (sessionToken.action !== 'ALLOW' || TOTPCheck) {
        const totpPrompt = await promptTotp(deviceId, userId);

        return {
            totpRequired: true,
            userId,
            expiresAt: totpPrompt.expiresAt
        };
    }

    // 8️⃣ Success
    return {
        success: true,
        sessionToken
    };
}

// ✅ Verify TOTP
export async function verifyTotp({ deviceId, userId, token }) {
    const totpRecord = await userDb.get(
        `SELECT * FROM totp WHERE deviceId = ? AND userId = ?`,
        [deviceId, userId]
    );
    if (!totpRecord || totpRecord.expiresAt < Date.now()) return false;
    const { TOTPSecretEnc, TOTPiv, TOTPTag } = await userDb.get(
        `SELECT TOTPSecretEnc, TOTPiv, TOTPTag FROM users WHERE userId = ?`,
        [userId]
    );
    const decipher = createDecipheriv(
        'aes-256-gcm',
        AES_SECRET,
        Buffer.from(TOTPiv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(TOTPTag, 'base64'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(TOTPSecretEnc, 'base64')),
        decipher.final()
    ]);
    const totpSecret = decrypted.toString('utf-8');
    const valid = speakeasy.totp.verify({ secret: totpSecret, encoding: 'base32', token });
    if (valid) {
        await userDb.run(
            `DELETE FROM totp WHERE deviceId = ? AND userId = ?`,
            [deviceId, userId]
        );
    }
    return valid;
}

export async function getUsernameById(userId){
    const result = await userDb.get(`SELECT username FROM users WHERE userId = ?`, [userId]);
    return result ? result.username : null;
}

export async function getAll(){
    const users = await userDb.getAll(`SELECT * FROM users`);
    const devices = await userDb.getAll(`SELECT * FROM deviceKeys`);
    const challenges = await userDb.getAll(`SELECT * FROM authChallenges`);
    const totp = await userDb.getAll(`SELECT * FROM totp`);
    return {users, devices, challenges, totp}
}

export async function getPublicKey(userId){
    const result = await userDb.get(
        `SELECT encryptPublic FROM deviceKeys WHERE userId = ?`,
        [userId]
    )
    return result ? result.encryptPublic : null;
}

export async function searchUsers(query, selfUserId) {
  return userDb.getAll(
    `
    SELECT userId, username
    FROM users
    WHERE username LIKE ?
      AND userId != ?
    `,
    [`%${query}%`, selfUserId]
  );
}

export async function promptTotp(deviceId, userId) {
  const now = Date.now();

  const existing = await userDb.get(
    `SELECT expiresAt FROM totp WHERE deviceId = ? AND userId = ?`,
    [deviceId, userId]
  );

  // Remove expired entry
  if (existing && existing.expiresAt < now) {
    await userDb.run(
      `DELETE FROM totp WHERE deviceId = ? AND userId = ?`,
      [deviceId, userId]
    );
  }

  // Create new TOTP challenge if none exists
  const challenge = await userDb.get(
    `SELECT expiresAt FROM totp WHERE deviceId = ? AND userId = ?`,
    [deviceId, userId]
  );

  if (!challenge) {
    const expiresAt = now + 5 * 60 * 1000; // 5 minutes
    await userDb.run(
      `INSERT INTO totp (deviceId, userId, expiresAt) VALUES (?, ?, ?)`,
      [deviceId, userId, expiresAt]
    );
    return { required: true, expiresAt };
  }

  return { required: true, expiresAt: challenge.expiresAt };
}




