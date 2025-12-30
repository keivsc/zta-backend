// FULL REWRITE WITH TRUE RANDOMNESS (IV STORED) + PER-USER KEY WRAPPING

import Database from "../src/db.js";
import { fileToBlob, getFileType } from "../src/utils.js";
import { randomUUID, randomBytes, createCipheriv, createDecipheriv } from "crypto";

const fileDb = new Database('filesv2.db');

// ─────────────────────────────────────────────
// AES HELPERS (with IV stored)
// ─────────────────────────────────────────────
function encryptAES(keyHex, buffer) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return {
    iv: iv.toString('hex'),
    data: encrypted.toString('hex')
  };
}

function decryptAES(keyHex, encryptedHex, ivHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const data = Buffer.from(encryptedHex, 'hex');
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ─────────────────────────────────────────────
// DB SETUP (with IV columns)
// ─────────────────────────────────────────────
await fileDb.run(`
  CREATE TABLE IF NOT EXISTS files(
    fileId TEXT PRIMARY KEY,
    type TEXT,
    filename TEXT,
    size INTEGER,
    content TEXT,
    iv TEXT,
    fileAesKey TEXT,
    ownerId TEXT,
    createdAt INTEGER,
    lastModified INTEGER
  )`);

await fileDb.run(`
  CREATE TABLE IF NOT EXISTS fileAccess(
    fileId TEXT,
    userId TEXT,
    aesKey TEXT,
    encryptedFileKey TEXT,
    iv TEXT,
    canRead BOOLEAN,
    canWrite BOOLEAN,
    createdAt INTEGER,
    updatedAt INTEGER,
    PRIMARY KEY (fileId, userId)
  )`);

// ─────────────────────────────────────────────
// CREATE FILE (file key → blank encrypted)
// ─────────────────────────────────────────────
export async function createFile(filename, ownerId, users) {
  const fileType = getFileType(filename);

  const { fileCount } = await fileDb.get(`SELECT COUNT(*) AS fileCount FROM files WHERE ownerId=?`, [ownerId]);
  if (fileCount >= 5) return { success:false, error:"Too many files created." };

  const fileId = randomUUID();
  const fileAesKey = randomBytes(32).toString('hex');
  const enc = encryptAES(fileAesKey, Buffer.from(""));

  await fileDb.run(`INSERT INTO files(fileId, filename, type, size, content, iv, fileAesKey, ownerId, createdAt, lastModified)
    VALUES(?,?,?,?,?,?,?,?,?,?)`,
    [fileId, filename, fileType, 0, enc.data, enc.iv, fileAesKey, ownerId, Date.now(), Date.now()]);

  await updatePermissions(fileId, ownerId, users);
  return { success:true, fileId };
}

// ─────────────────────────────────────────────
// UPDATE PERMISSIONS (store encrypted fileKey per user)
// ─────────────────────────────────────────────
export async function updatePermissions(fileId, ownerId, users) {
  const file = await fileDb.get(`SELECT fileAesKey, ownerId FROM files WHERE fileId=?`, [fileId]);
  if (!file) return { success:false, error:"File does not exist." };
  if (file.ownerId !== ownerId) return { success:false, error:"Only owner may update permissions." };

  const now = Date.now();

  for (const u of users) {
    const { userId, read, write } = u;

    const userAesKey = randomBytes(32).toString('hex');
    const wrapped = encryptAES(userAesKey, Buffer.from(file.fileAesKey, 'hex'));

    const existing = await fileDb.get(`SELECT 1 FROM fileAccess WHERE fileId=? AND userId=?`, [fileId, userId]);

    if (existing) {
      await fileDb.run(`UPDATE fileAccess SET canRead=?, canWrite=?, aesKey=?, encryptedFileKey=?, iv=?, updatedAt=?
        WHERE fileId=? AND userId=?`,
        [read?1:0, write?1:0, userAesKey, wrapped.data, wrapped.iv, now, fileId, userId]);
    } else {
      await fileDb.run(`INSERT INTO fileAccess(fileId,userId,aesKey,encryptedFileKey,iv,canRead,canWrite,createdAt,updatedAt)
        VALUES(?,?,?,?,?,?,?,?,?)`,
        [fileId, userId, userAesKey, wrapped.data, wrapped.iv, read?1:0, write?1:0, now, now]);
    }
  }

  return { success:true };
}

// ─────────────────────────────────────────────
// UPDATE FILE (decrypt using file key → encrypt using file key with new IV)
// ─────────────────────────────────────────────
export async function updateFile(fileId, userId, encryptedFromUser) {
  const row = await fileDb.get(`
    SELECT f.ownerId, f.fileAesKey, fa.canWrite, fa.aesKey AS userAesKey
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId=fa.fileId AND fa.userId=?
    WHERE f.fileId=?`,
    [userId, fileId]
  );

  if (!row) return { success:false, error:"File not found" };

  const isOwner = row.ownerId === userId;
  if (!isOwner && !row.canWrite) return { success:false, error:"No write permission" };

  let plaintext;

  if (isOwner) {
    const blob = fileToBlob(encryptedFromUser);
    plaintext = Buffer.from(await blob.arrayBuffer());
  } else {
    const { data, iv } = encryptedFromUser;
    try {
      plaintext = decryptAES(row.userAesKey, data, iv);
    } catch(err) {
      return { success:false, error:"Decrypt failed: "+err.message };
    }
  }

  const enc = encryptAES(row.fileAesKey, plaintext);

  await fileDb.run(`UPDATE files SET content=?, iv=?, size=?, lastModified=? WHERE fileId=?`,
    [enc.data, enc.iv, plaintext.length, Date.now(), fileId]);

  return { success:true };
}

// ─────────────────────────────────────────────
// FETCH FILE (decrypt file → re-encrypt with user key)
// ─────────────────────────────────────────────
export async function getFile(fileId, userId) {
  const row = await fileDb.get(`
    SELECT f.*, fa.canRead, fa.canWrite, fa.aesKey AS userAesKey, fa.encryptedFileKey, fa.iv AS userIv
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId=fa.fileId AND fa.userId=?
    WHERE f.fileId=?`,
    [userId, fileId]
  );

  if (!row) return { error:"File not found" };

  const isOwner = row.ownerId === userId;
  if (!isOwner && !row.canRead) return { error:"No read permission" };

  const plaintext = decryptAES(row.fileAesKey, row.content, row.iv);

  if (isOwner) {
    return {
      fileId: row.fileId,
      filename: row.filename,
      size: row.size,
      type: row.type,
      content: plaintext.toString(),
      ownerId: row.ownerId,
      createdAt: row.createdAt,
      lastModified: row.lastModified,
      canRead: true,
      canWrite: true
    };
  }

  const enc = encryptAES(row.userAesKey, plaintext);

  return {
    fileId: row.fileId,
    filename: row.filename,
    size: row.size,
    type: row.type,
    content: { data: enc.data, iv: enc.iv },
    ownerId: row.ownerId,
    createdAt: row.createdAt,
    lastModified: row.lastModified,
    canRead: true,
    canWrite: !!row.canWrite
  };
}

// ─────────────────────────────────────────────
// DELETE FILE
// ─────────────────────────────────────────────
export async function deleteFile(fileId, userId) {
  const owner = await fileDb.get(`SELECT 1 FROM files WHERE fileId=? AND ownerId=?`, [fileId, userId]);
  if (!owner) return { success:false, error:"Not authorized" };

  await fileDb.run(`DELETE FROM files WHERE fileId=?`, [fileId]);
  await fileDb.run(`DELETE FROM fileAccess WHERE fileId=?`, [fileId]);

  return { success:true };
}

// ─────────────────────────────────────────────
// GET ALL FILES
// ─────────────────────────────────────────────
export async function getAllFiles(userId) {
  const rows = await fileDb.getAll(
    `
    SELECT 
      f.fileId,
      f.filename AS name,
      f.size,
      CASE WHEN f.ownerId = ? THEN 1 ELSE fa.canRead END AS canRead,
      CASE WHEN f.ownerId = ? THEN 1 ELSE fa.canWrite END AS canWrite
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
    WHERE f.ownerId = ? OR fa.canRead = 1
    `,
    [userId, userId, userId, userId]
  );

  return rows.map(r => ({
    fileId: r.fileId,
    filename: r.name,
    size: r.size,
    canRead: !!r.canRead,
    canWrite: !!r.canWrite
  }));
}
