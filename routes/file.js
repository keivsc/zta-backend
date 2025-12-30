import express from 'express';
import Logger from '../src/logging.js';
import { verifyToken } from '../services/session.js';
import { 
  getFile, 
  updateFile, 
  deleteFile, 
  createFile, 
  updatePermissions, 
  getAllFiles, 
  getUploadKeys, 
  uploadFileGeneric,
  getAllFilesDebug
} from '../services/file.js';
import { randomUUID } from 'crypto';
import { requireDebugAuth, requireSession } from '../src/utils.js';


const router = express.Router();
const logger = new Logger('api');



router.get('/files-debug', requireDebugAuth, async (req, res) => {
    const { files, access } = await getAllFilesDebug();

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Files Debug</title>
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
            <h1>Files Debug Tables</h1>
            ${renderTable('Files', files)}
            ${renderTable('File Access', access)}
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



router.use(requireSession);

// Create new file
router.post('/create', async (req, res) => {
  const { filename, users } = req.body;
  if (!filename) return res.status(400).json({ error: "Missing file name." });

  try {
    const file = await createFile(filename, req.userId, users);
    return res.status(200).json(file);
  } catch (err) {
    logger.error('Create file error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Delete file
router.delete('/delete/:fileId', async (req, res) => {
  const fileId = req.params.fileId;
  if (!fileId) return res.status(400).json({ error: "Missing file id." });

  try {
    const file = await deleteFile(fileId, req.userId);
    if (!file.success) return res.status(404).json(file);
    return res.status(200).json(file);
  } catch (err) {
    logger.error('Delete file error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Get upload keys for a file
router.get('/modify/options/:fileId', async (req, res) => {
  const fileId = req.params.fileId;
  if (!fileId) return res.status(400).json({ error: "Missing file id." });

  try {
    const keys = await getUploadKeys(fileId, req.userId);
    if (keys.error) return res.status(400).json(keys);
    return res.status(200).json(keys);
  } catch (err) {
    logger.error('Get upload keys error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Modify/update file using upload key
router.put('/modify/:fileId', async (req, res) => {
  const fileId = req.params.fileId;
  const encryptedContent = req.body;
  if (!fileId || !encryptedContent) return res.status(400).json({ error: "Missing body." });

  try {
    const file = await updateFile(fileId, req.userId, encryptedContent);
    if (!file.success) return res.status(400).json(file);
    return res.status(200).json(file);
  } catch (err) {
    logger.error('Update file error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Update permissions
router.put('/perms/:fileId', async (req, res) => {
  const fileId = req.params.fileId;
  const { users } = req.body;
  if (!fileId || !users) return res.status(400).json({ error: "Missing body." });

  try {
    const perms = await updatePermissions(fileId, req.userId, users);
    if (!perms.success) return res.status(400).json(perms);
    return res.status(200).json(perms);
  } catch (err) {
    logger.error('Update permissions error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Get all files
router.get('/all', async (req, res) => {
  try {
    const fileArray = await getAllFiles(req.userId);
    return res.status(200).json({ files: Array.isArray(fileArray) ? fileArray : [] });
  } catch (err) {
    logger.error('Get all files error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.get('/upload/options', async (req, res) => {
  try {
    const keys = await getUploadKeys(randomUUID(), req.userId);
    if (keys.error) return res.status(400).json(keys);
    return res.status(200).json(keys);
  } catch (err) {
    logger.error('Get upload keys error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.post('/upload', async(req, res)=>{
  const encryptedContent = req.body.encryptedContent;
  const filename = req.body.filename;
  if (!encryptedContent || !filename) return res.status(400).json({ error: "Missing body." });

  try {
    const file = await uploadFileGeneric(filename, req.userId, encryptedContent);
    if (!file.success) return res.status(400).json(file);
    return res.status(200).json(file);
  } catch (err) {
    logger.error('Update file error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
})

// Get file (with session check)
router.get('/:fileId', async (req, res) => {
  const fileId = req.params.fileId;

  try {
    const file = await getFile(fileId, req.userId);
    if (!file || file.error) return res.status(404).json(file.error ? { error: file.error } : { error: "File not found." });
    return res.status(200).json(file);
  } catch (err) {
    logger.error('Get file error', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});





export default router;


