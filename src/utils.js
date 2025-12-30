
import crypto from 'crypto';
import { verifyToken } from '../services/session.js';
import { promptTotp } from '../services/user.js';


export function toPEM(base64Key) {
  // Decode from base64 back to binary
  const der = Buffer.from(base64Key, 'base64');

  // Convert to PEM
  const b64 = der.toString('base64');
  const pem =
    `-----BEGIN PUBLIC KEY-----\n` +
    b64.match(/.{1,64}/g).join('\n') +
    `\n-----END PUBLIC KEY-----`;

  return pem;
}

export function randomString(length = 6) {
    return crypto.randomBytes(length)
                 .toString('base64')
                 .replace(/[^a-zA-Z0-9]/g, '') 
                 .slice(0, length);
}

export function getFileType(filename) {
  const parts = filename.split('.');
  if (parts.length > 1) {
    return '.' + parts.pop();
  } else {
    return '.txt';
  }
}


export function fileToBlob(content) {
  const maxSize = 5 * 1024 * 1024; // 5 MB 

  let buffer;
  if (typeof content === 'string') {
    buffer = Buffer.from(content, 'utf-8');
  } else if (content instanceof Uint8Array) {
    buffer = Buffer.from(content);
  } else if (Buffer.isBuffer(content)) {
    buffer = content;
  } else {
    throw new Error('Unsupported file content type');
  }

  if (buffer.length > maxSize) {
    throw new Error('File exceeds 5 MB limit');
  }

  const blob = new Blob([buffer]);
  return blob;
}


export function requireDebugAuth(req, res, next) {
  // --- Basic Auth check ---
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Debug"');
    return res.status(401).send('Authentication required');
  }

  const [user, pass] = Buffer
    .from(auth.split(' ')[1], 'base64')
    .toString()
    .split(':');

  if (user !== DEBUG_USER || pass !== DEBUG_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Debug"');
    return res.status(401).send('Invalid credentials');
  }

  // --- IP check ---
  // Whitelist of allowed IPs
  const allowedIp = process.env.ALLOWED_IP
  const clientIp = req.headers['true-client-ip']
  if (allowedIp !== clientIp) {
    return res.status(403).send(`Forbidden: IP ${clientIp} not allowed`);
  }

  next();
}

export async function requireSession(req, res, next) {
    const token = req.cookies['session'];
    const deviceId = req.cookies['x-device-id'];

    if (!token || !deviceId) {
        return res.status(401).json({ error: "Missing session." });
    }

    const result = await verifyToken(token, deviceId, getClientIp(req));

    switch(result.action) {
      case "DENY":
        return res.status(401).json({ error: "Invalid session." });
      case "STEP_UP":
        const totpPrompt = await promptTotp(
            req.cookies['x-device-id'],
            result.userId
        );

        return res.status(401).json({
            error: "Re-authentication required",
            stepUp: "TOTP",
            TOTPExpiry: totpPrompt.expiresAt,
            userId: result.userId
        });
      case "ALLOW":
        req.userId = result.userId;
        return next();
      default:
        return res.status(500).json({ error: "Internal server error." });
    }
}


export function getClientIp(req) {
    return req.headers['true-client-ip'] || req.ip;
}

