import { publicEncrypt, constants, pbkdf2, createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { toPEM } from './utils.js';

export function encryptKey(publicKey, wrapKey) {
  return publicEncrypt(
    {
      key: toPEM(Buffer.from(publicKey, "base64")),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(wrapKey)
  ).toString('base64');
}

export function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        pbkdf2(
            password,
            salt,
            200000,
            32,
            "sha256",
            (err, derivedKey) => {
                if (err) return reject(err);

                resolve({
                    hash: derivedKey.toString("base64"),
                    salt: Buffer.from(salt).toString("base64")
                });
            }
        );
    });
}


export function decryptGCM({ encrypted, iv, tag }, keyB64) {
  const key = Buffer.from(keyB64, "base64");
  const ivBuf = Buffer.from(iv, "base64");
  const tagBuf = Buffer.from(tag, "base64");
  const data = Buffer.from(encrypted, "base64");

  const decipher = createDecipheriv("aes-256-gcm", key, ivBuf);
  decipher.setAuthTag(tagBuf);

  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

export function decryptGCMBuffer({ encrypted, iv, tag }, keyB64) {
  const key = Buffer.from(keyB64, "base64"); // AES key
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  // decrypt and return as UTF-8 string
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

export function encryptGCM(plaintext, key) {
  const iv = randomBytes(12);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    text: encrypted.toString("base64")
  };
}

export async function generateRSAKey() {
  const keyPair = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Export keys as Base64
  const publicKey = await subtle.exportKey("spki", keyPair.publicKey);
  const privateKey = await subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64")
  };
}

