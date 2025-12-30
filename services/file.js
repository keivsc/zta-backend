import { decryptGCM, decryptGCMBuffer, encryptGCM, encryptKey } from "../src/crypto.js";
import Database from "../src/db.js";
import { getFileType } from "../src/utils.js";
import { randomBytes, randomUUID} from 'crypto';
import { getPublicKey } from "./user.js";

const fileDb = new Database('files.db');

await fileDb.run(
  `CREATE TABLE IF NOT EXISTS files(
    fileId TEXT PRIMARY KEY,
    type TEXT,
    filename TEXT,
    size INTEGER,
    content TEXT,
    aesKey TEXT,
    aesIV TEXT,
    aesTag TEXT,
    ownerId TEXT,
    createdAt INTEGER,
    lastModified INTEGER
  )`
)

await fileDb.run(
  `CREATE TABLE IF NOT EXISTS fileAccess(
    fileId TEXT,
    userId TEXT,
    canRead BOOLEAN,
    canWrite BOOLEAN
  )`
)

await fileDb.run(
  `CREATE TABLE IF NOT EXISTS fileUploadKeys(
  fileId TEXT PRIMARY KEY,
  userId TEXT, 
  aesKey TEXT)`
)



export async function getFile(fileId, userId) {
  if (!userId) {
    return {};
  }

  const row = await fileDb.get(
    `
    SELECT 
      f.fileId,
      f.filename,
      f.size,
      f.type,
      f.ownerId,
      f.createdAt,
      f.lastModified,
      f.aesKey,
      f.aesTag,
      f.aesIV,
      fa.canRead,
      fa.canWrite,
      CASE WHEN fa.canRead = 1 OR f.ownerId = ? THEN f.content ELSE NULL END AS content
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
    WHERE f.fileId = ?
  `,
    [userId, userId, fileId]
  )

  if (!row) return { error: "File does not exist." }

  if (!row.canRead && row.ownerId !== userId) {
    return {}
  }

  const isOwner = row.ownerId === userId

  let contentString = {};
  let wrappedKey;


  if (row.content) {
    const decryptedContent = decryptGCM({encrypted:row.content, iv:row.aesIV, tag:row.aesTag}, row.aesKey);
    const userPublicKey = await getPublicKey(userId);
    if (!userPublicKey){
      throw new Error("Invalid userId");
    }
    const userAESKey = randomBytes(32);
    const encryptedContent = encryptGCM(decryptedContent, userAESKey);
    wrappedKey = encryptKey(userPublicKey, userAESKey);
    encryptedContent.aesKey = wrappedKey;
    contentString = encryptedContent;
  }


  return {
    fileId: row.fileId,
    filename: (row.filename+row.type),
    size: row.size,
    type: row.type,
    content: contentString,
    ownerId: row.ownerId,
    createdAt: row.createdAt,
    lastModified: row.lastModified,
    canRead: isOwner ? true : !!row.canRead,
    canWrite: isOwner ? true : !!row.canWrite
  }
}

export async function createFile(filename, userId, users){

  const fileType = getFileType(filename);
  filename = filename.replace(/\.[^/.]+$/, ""); 
  const {fileCount} = await fileDb.get(
    `SELECT COUNT(*) as fileCount from files WHERE ownerId = ?`,
    [userId]
  );
  if (fileCount >= 5){
    return {success:false, error:'Too many files created.'}
  }
  const fileId = randomUUID()
  await fileDb.run(
    `INSERT INTO files(fileId, filename, type, size, content, ownerId, createdAt, lastModified)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
    [fileId, filename, fileType, 0, "", userId, Date.now(), Date.now()]
  );

  await updatePermissions(fileId, users);

  return {success:true, fileId};

}

export async function getUploadKeys(fileId, userId){
  const keys = await fileDb.get(
    `SELECT * FROM fileUploadKeys WHERE fileId = ?`,
    [fileId]
  );
  if (keys){
    if (keys.userId == userId){
      await fileDb.run(
        `DELETE FROM fileUploadKeys WHERE fileId = ? and userId = ?`,
        [fileId, userId]
      )
    }else{
      return {error:"File is in process of saving"}
    }
  }
  const aesKey = randomBytes(32);
  await fileDb.run(
    `INSERT INTO fileUploadKeys(fileId, userId, aesKey)
    VALUES(?, ?, ?)`,
    [fileId, userId, aesKey.toString('base64')]
  )
  const userPublicKey = await getPublicKey(userId);
  const wrappedKey = encryptKey(userPublicKey, aesKey);
  return {aesKey: wrappedKey}
}


export async function updateFile(fileId, userId, encryptedContent) {
  const fileAccess = await fileDb.get(
    `SELECT 
      CASE 
        WHEN f.ownerId = ? THEN 1
        ELSE fa.canWrite
      END AS hasWriteAccess
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
    WHERE f.fileId = ?`,
    [userId, userId, fileId]
  );

  if (!fileAccess || !fileAccess.hasWriteAccess) {
    return { success: false, error: "Invalid fileId / Missing permissions" };
  }

  // Get AES key for this upload session
  const uploadKeyRow = await fileDb.get(
    `SELECT aesKey FROM fileUploadKeys WHERE fileId = ? AND userId = ?`,
    [fileId, userId]
  );
  if (!uploadKeyRow) {
    return { success: false, error: "No upload key found. Call /options first." };
  }

  try {
    // Decrypt the content using AES key
    const decrypted = decryptGCM(encryptedContent, uploadKeyRow.aesKey);

    const aesKey = randomBytes(32);
    const encryptedStorage = encryptGCM(decrypted, aesKey);

    await fileDb.run(
      `UPDATE files SET content = ?, aesKey = ?, aesIV = ?, aesTag = ?, size = ?, lastModified = ? WHERE fileId = ?`,
      [encryptedStorage.text, aesKey.toString('base64'), encryptedStorage.iv, encryptedStorage.tag, (new TextEncoder()).encode(decrypted).length, Date.now(), fileId]
    );

    // Delete used upload key
    await fileDb.run(
      `DELETE FROM fileUploadKeys WHERE fileId = ? AND userId = ?`,
      [fileId, userId]
    );

    return { success: true, fileId };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function uploadFileGeneric(filename, userId, encryptedContent) {
  // Get AES key for this upload session
  const uploadKeyRow = await fileDb.get(
    `SELECT aesKey FROM fileUploadKeys WHERE userId = ?`,
    [userId]
  );

  if (!uploadKeyRow) {
    return { success: false, error: "No upload key found. Call /options first." };
  }

  try {
    // Decrypt incoming content using upload session AES key

    const decryptedBuffer = decryptGCM(encryptedContent, uploadKeyRow.aesKey);

    // Re-encrypt content for storage with a fresh AES key
    const aesKey = randomBytes(32);
    const encryptedStorage = encryptGCM(decryptedBuffer, aesKey); // returns { text: Buffer, iv, tag }

    const fileId = randomUUID();
    const fileType = getFileType(filename);

    await fileDb.run(
      `INSERT INTO files(fileId, filename, type, size, content, aesKey, aesIV, aesTag, ownerId, createdAt, lastModified)
       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fileId,
        filename,
        fileType,
        decryptedBuffer.length,        // actual size in bytes
        encryptedStorage.text,         // store as Buffer
        aesKey.toString("base64"),
        encryptedStorage.iv,
        encryptedStorage.tag,
        userId,
        Date.now(),
        Date.now()
      ]
    );

    // Optionally delete the upload session key
    await fileDb.run(
      `DELETE FROM fileUploadKeys WHERE userId = ? AND fileId = ?`,
      [userId, encryptedContent.fileId]
    );

    return { success: true, fileId };
  } catch (err) {

    return { success: false, error: err.message };
  }
}

export async function deleteFile(fileId, userId){
  const isOwner = await fileDb.get(
    `SELECT 1 FROM files WHERE ownerId = ? AND fileId = ?`,
    [userId, fileId]
  );

  if (!isOwner){
    return {success:false, error:"File does not exist."}
  }

  await fileDb.run(
    `DELETE FROM files WHERE fileId = ?`,
    [fileId]
  );
  await fileDb.run(
    `DELETE FROM fileAccess WHERE fileId = ?`,
    [fileId]
  );
  return {success:true};

}

export async function updatePermissions(fileId, ownerUserId, users) {
    const file = await fileDb.get(
        `SELECT ownerId FROM files WHERE fileId = ?`,
        [fileId]
    );

    if (!file) {
        return { success: false, error: "File does not exist." };
    }

    if (file.ownerId !== ownerUserId) {
        return { success: false, error: "Only the owner can change permissions." };
    }

    if (!Array.isArray(users) || users.length === 0) {
        return { success: false, error: "Users not an array or is not included." };
    }

    const now = Date.now();

    for (const u of users) {
        const { userId, read, write } = u;

        const existing = await fileDb.get(
            `SELECT * FROM fileAccess WHERE fileId = ? AND userId = ?`,
            [fileId, userId]
        );

        if (existing) {
            await fileDb.run(
                `UPDATE fileAccess 
                 SET canRead = ?, canWrite = ?, updatedAt = ? 
                 WHERE fileId = ? AND userId = ?`,
                [read ? 1 : 0, write ? 1 : 0, now, fileId, userId]
            );
        } else {
            await fileDb.run(
                `INSERT INTO fileAccess (fileId, userId, canRead, canWrite, createdAt, updatedAt)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [fileId, userId, read ? 1 : 0, write ? 1 : 0, now, now]
            );
        }
    }

    return { success: true, users };
}

export async function getAllFiles(userId) {
    const rows = await fileDb.getAll(
        `
        SELECT 
            f.fileId,
            f.filename,
            f.type,
            f.size,
            CASE 
                WHEN f.ownerId = ? THEN 1
                ELSE fa.canRead
            END AS canRead,
            CASE 
                WHEN f.ownerId = ? THEN 1
                ELSE fa.canWrite
            END AS canWrite
        FROM files f
        LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
        WHERE f.ownerId = ? OR fa.canRead = 1
        `,
        [userId, userId, userId, userId]
    );

    return rows.map(row => ({
        fileId: row.fileId,
        filename: (row.filename+row.type),
        size: row.size,
        canRead: !!row.canRead,
        canWrite: !!row.canWrite
    }));
}


export async function getAllFilesDebug() {
    const files = await fileDb.getAll(`
        SELECT fileId, filename, type, size, ownerId, createdAt, lastModified 
        FROM files
    `);
    const access = await fileDb.getAll(`
        SELECT fileId, userId, canRead, canWrite 
        FROM fileAccess
    `);
    return { files, access };
}