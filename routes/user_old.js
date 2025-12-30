import express from 'express';
import Database from '../src/db.js';
import { randomBytes } from "crypto";
import Logger from '../src/logging.js';
import { toPEM } from '../src/utils.js'
import { encryptKey } from '../src/crypto.js';

import speakeasy from 'speakeasy';

const logger = new Logger('user');

const userDb = new Database("users.db");

await userDb.run(`CREATE TABLE IF NOT EXISTS Users (
    userId TEXT PRIMARY KEY,
    username TEXT,
    email TEXT UNIQUE,
    publicKey TEXT,
    privateKey TEXT,
    keySalt TEXT,
    keyIV TEXT,
    passwordHash TEXT,
    passwordSalt TEXT,
    deviceIds ARRAY,
    fingerprintIds ARRAY,
    TOTPSecret TEXT,
    loginAttempts INTEGER DEFAULT 0,
    lastLoginAttempt TIMESTAMP
)`) // add TOTP RSA key

await userDb.run(`CREATE TABLE IF NOT EXISTS UserChallenges(
  userId TEXT PRIMARY KEY,
  ChallengeText TEXT,
  ExpiresAt INTEGER 
)`)

await userDb.run(`CREATE TABLE IF NOT EXISTS UserTOTP(
  userId TEXT PRIMARY KEY,
  ExpiresAt INTEGER 
)`)

const router = express.Router();

router.get('/', (req, res) => {
    res.send('User route is working');
});

router.get('/email/:email', async (req, res) => {
    const email = req.params.email;
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const user = await userDb.get(
            'SELECT * FROM Users WHERE email = ?',
            [email]
        );

        if (!user) {
            return res.status(200).json({email: "Email Available"});
        }

        return res.status(409).json({email: "Email Already Registered"});
    } catch (err) {
        logger.error('Error fetching user by email', err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

router.post('/register', async (req, res) => {
    const { username, email, publicKey, privateKey, keySalt, keyIV, passwordHash, passwordSalt} = req.body;
    if (!username || !email || !publicKey || !privateKey || !keySalt || !keyIV || !passwordHash || !passwordSalt) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const existingUser = await userDb.get(
            'SELECT * FROM Users WHERE email = ?',
            [email]
        );

        if (existingUser) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        const userId = crypto.randomUUID();

        const deviceId = req.cookies.device_id;
        const fingerprintId = req.cookies.fingerprint_id;

        await userDb.run(
          `INSERT INTO Users (userId, username, email, publicKey, privateKey, keySalt, keyIV, passwordHash, passwordSalt, deviceIds, fingerprintIds)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, username, email, publicKey, privateKey, keySalt, keyIV, passwordHash, passwordSalt, JSON.stringify([deviceId]), JSON.stringify([fingerprintId])]
        );
        
        logger.info(`New User Created: [${userId}] ${username}`);

        return res.status(201).json({ message: 'User registered successfully', "userId": userId });

    } catch (err) {
        logger.error('Error during registration', err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});


router.get('/TOTP/setup/:email', async (req, res) => {
  const email = req.params.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await userDb.get(
      'SELECT TOTPSecret, publicKey FROM Users WHERE email = ?',
      [email]
    );

    if (!user || !user.publicKey) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.TOTPSecret) {
      return res.status(400).json({ error: 'TOTP already set up for this user' });
    }

    const secret = speakeasy.generateSecret({ length: 20 });

    const otpauthURL = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `YourApp:${email}`,
      issuer: 'YourApp',
      encoding: 'base32',
    });

    await userDb.run(
      'UPDATE Users SET TOTPSecret = ? WHERE email = ?',
      [secret.base32, email]
    );


    const encryptedOtpauthURL = encryptKey(user.publicKey, otpauthURL);

    return res.status(200).json({ otpauthURL: encryptedOtpauthURL });

  } catch (err) {
    logger.error('Error during TOTP setup', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.get('/salt/:email', async (req, res)=>{
  const email = req.params.email;
  if (!email){
    return res.status(400).json({ error: "Missing Required Fields" });
  }

  const salt = await userDb.get(
    'SELECT passwordSalt FROM Users WHERE email = ?',
    [email]
  );

  if (!salt){
    return res.status(400).json({ error: "User does not exist." });
  }

  return res.status(200).json({ data: { passwordSalt: salt.passwordSalt } })
});

router.post('/login', async (req, res)=>{

  const { email, passwordHash } = req.body;

  if (!email){
    return res.status(400).json({ error: "Missing Required Fields" });
  }

  const authCheck = await userDb.get(
    'SELECT userId, publicKey, keySalt, keyIV, privateKey FROM Users where email = ? AND passwordHash = ?',
    [email, passwordHash]
  );
  if (!authCheck){
    return res.json(401).json({ error: "Email or Password mismatch!" });
  }

  const challenge = randomBytes(32).toString('base64');

  const encryptedChallenge = encryptKey(authCheck.publicKey, challenge);

  try{
    await userDb.run(
      `INSERT INTO UserChallenges(userId, ChallengeText, ExpiresAt)
      VALUES(?, ?, ?)`,
      [authCheck.userId, challenge, Date.now() + 60000]
    );
  }catch(err){
    await userDb.run(
      'DELETE FROM UserChallenges WHERE userId = ?',
      [authCheck.userId]
    );
    return res.status(401).json({ error: "Duplicate Challenge Request" })
  }

  return res.status(200).json({data:{ userId:authCheck.userId, challengeText:encryptedChallenge, salt:authCheck.keySalt, iv:authCheck.keyIV, key:authCheck.privateKey } });

})

router.post('/challenge', async (req, res)=>{
  const {userId, text} = req.body;

  if (!userId || !text){
    return res.status(400).json({ error: "Missing Required Fields." });
  }

  const challengeCheck = await userDb.get(
    'SELECT * FROM UserChallenges WHERE userId = ? AND challengeText = ?',
    [userId, text]
  );

  if (!challengeCheck){
    return res.status(401).json({ error:"401 Unauthorized." });
  }else if(challengeCheck.ExpiresAt < Date.now()){
    await userDb.run(
      'DELETE FROM UserChallenges WHERE userId = ?',
      [userId]
    );
    return res.status(401).json({ error:"Challenge Expired." });
  }

  const TOTPExpiry = Date.now() + 180000

  try{
    await userDb.run(
      `INSERT INTO UserTOTP(userId, ExpiresAt)
      VALUES(?, ?)`,
      [userId, TOTPExpiry]
    )
  }catch(_){};

  return res.status(200).json({ data:{userId: userId, TOTPExpiry: TOTPExpiry} });

})

router.post('/TOTP', async (req, res)=>{
  const {userId, code} = req.body;

  if (!userId || !code){
    return res.status(400).json({ error: "Missing Required Fields." });
  }

  const userTOTPSecret = await userDb.getOne(
    'SELECT TOTPSecret FROM Users WHERE userId = ?',
    [userId]
  );

  if(!userTOTPSecret){
    return res.status(400).json({ error:"User does not exist." });
  }else if(!userTOTPSecret.TOTPSecret){
    return res.status(401).json({ error: "401 Unauthorized." });
  }

  const TOTPRecord = await userDb.get(
    'SELECT * FROM UserTOTP WHERE userId = ?',
    [userId]
  );

  
  if(!TOTPRecord){
    return res.status(400).json({ error: "Text Challenge not passed." })
  }else if (TOTPRecord.ExpiresAt < Date.now()){
    return res.status(401).json({ error: "TOTP Expired." })
  }

  const TOTPCheck = speakeasy.totp.verify({
    secret: userTOTPSecret.TOTPSecret,
    encoding: 'base32',
    token: code
  })

  if (TOTPCheck){
    return res.status(200).json({ message: "TOTP Verified.", data: ""})
  }else{
    return res.status(401).json({ error:"TOTP Mismatch", data:{ TOTPExpiry:TOTPRecord.ExpiresAt } })
  }

})


export default router;


// Use session token for authentication in future routes | Session token can only be generated after TOTP verification


