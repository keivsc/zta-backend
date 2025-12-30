import express from 'express';
import Logger from '../src/logging.js';
import { verifyToken } from '../services/session.js';
import { 
  createFile,
  deleteFile,
  updateFile,
  updatePermissions,
  getAllFiles,
  getFile
} from '../services/filev2.js';

const router = express.Router();
const logger = new Logger('api');

// Create file
router.post('/create', async (req, res) => {
  try {
    const { filename, users } = req.body;
    if (!filename) return res.status(400).json({ error: "Missing file name." });

    const result = await createFile(filename, req.userId, users || []);
    return res.status(200).json(result);
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete file
router.delete('/delete/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    if (!fileId) return res.status(400).json({ error: "Missing file id." });

    const result = await deleteFile(fileId, req.userId);
    if (!result.success) return res.status(404).json(result);
    return res.status(200).json(result);
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Modify file (encrypted upload)
router.put('/modify/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    const { encrypted, iv } = req.body;

    if (!fileId || !encrypted || !iv)
      return res.status(400).json({ error: "Missing encrypted content or iv." });

    const result = await updateFile(fileId, req.userId, { encrypted, iv });
    if (!result.success) return res.status(400).json(result);
    return res.status(200).json(result);
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Update permissions
router.put('/perms/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    const { users } = req.body;

    if (!fileId || !users)
      return res.status(400).json({ error: "Missing body." });

    const result = await updatePermissions(fileId, users);
    if (!result.success) return res.status(400).json(result);

    return res.status(200).json(result);
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// List all accessible files
router.get('/all', async (req, res) => {
  try {
    const list = await getAllFiles(req.userId);
    return res.status(200).json({ files: Array.isArray(list) ? list : [] });
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single file (returns encrypted for non-owner)
router.get('/:fileId', async (req, res) => {
  try {
    const result = await getFile(req.params.fileId, req.userId);
    if (!result) return res.status(404).json({ error: "File not found." });

    return res.status(200).json(result);
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
