import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimiter from 'express-rate-limit';
import Logger from './src/logging.js';

import userRoutes from './routes/user.js';
import fileRoutes from './routes/file.js';
import deviceRoutes from './routes/device.js';


dotenv.config({quiet:true});
const logger = new Logger('main');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware setup
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? process.env.FRONTEND_URL
    : 'http://localhost:5173',
  credentials: true,
}));


app.use(cookieParser());
app.use(express.json());

// Routes
app.use('/user', userRoutes);
app.use('/file', fileRoutes);
app.use('/device',deviceRoutes)


// Start server
app.listen(PORT, () => {
  logger.info(`CORS allowed: ${process.env.FRONTEND_URL}`)
  logger.info(`Express server running on http://localhost:${PORT}`);
});