// @ts-nocheck -- JWT request augmentation is narrowed by Auth route contracts.
import jwt from 'jsonwebtoken';

import { IS_PLATFORM } from '@/shared/utils.js';
import { userDb, appConfigDb } from '../database/index.js';

// In hosted deployments set JWT_SECRET so sessions survive filesystem resets.
const JWT_SECRET = process.env.JWT_SECRET || appConfigDb.getOrCreateJwtSecret();

const validateApiKey = (req, res, next) => {
  if (!process.env.API_KEY) return next();
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.API_KEY) return res.status(401).json({ error: 'Invalid API key' });
  next();
};

const authenticateToken = async (req, res, next) => {
  if (IS_PLATFORM) {
    try {
      const user = userDb.getFirstUser();
      if (!user) return res.status(500).json({ error: 'Platform mode: No user found in database' });
      req.user = user;
      return next();
    } catch (error) {
      console.error('Platform mode error:', error);
      return res.status(500).json({ error: 'Platform mode: Failed to fetch user' });
    }
  }

  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];
  if (!token && req.query.token) token = req.query.token;
  if (!token) {
    res.setHeader('X-Auth-Error', 'invalid-token');
    return res.status(401).json({ error: 'Access denied. No token provided.', code: 'AUTH_TOKEN_INVALID' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    let user = userDb.getUserById(decoded.userId);

    // Render Free has an ephemeral filesystem. If SQLite disappeared after a
    // restart/spin-down, a valid JWT still represents the signed-in user.
    // Reconstruct the minimal authenticated identity from the signed token.
    if (!user && decoded.userId && typeof decoded.username === 'string') {
      user = { id: decoded.userId, username: decoded.username };
    }

    if (!user) {
      res.setHeader('X-Auth-Error', 'invalid-token');
      return res.status(401).json({ error: 'Invalid token. User not found.', code: 'AUTH_TOKEN_INVALID' });
    }

    if (decoded.exp && decoded.iat) {
      const now = Math.floor(Date.now() / 1000);
      const halfLife = (decoded.exp - decoded.iat) / 2;
      if (now > decoded.iat + halfLife) res.setHeader('X-Refreshed-Token', generateToken(user));
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      res.setHeader('X-Auth-Error', 'session-expired');
      return res.status(401).json({ error: 'Session expired. Please log in again.', code: 'AUTH_TOKEN_EXPIRED' });
    }
    console.warn('Token verification failed:', error instanceof Error ? error.message : String(error));
    res.setHeader('X-Auth-Error', 'invalid-token');
    return res.status(401).json({ error: 'Invalid token', code: 'AUTH_TOKEN_INVALID' });
  }
};

const generateToken = (user) => jwt.sign(
  { userId: user.id, username: user.username },
  JWT_SECRET,
  { expiresIn: '30d' },
);

const authenticateWebSocket = (token) => {
  if (IS_PLATFORM) {
    try {
      const user = userDb.getFirstUser();
      return user ? { id: user.id, userId: user.id, username: user.username } : null;
    } catch (error) {
      console.error('Platform mode WebSocket error:', error);
      return null;
    }
  }
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = userDb.getUserById(decoded.userId) || (
      decoded.userId && typeof decoded.username === 'string'
        ? { id: decoded.userId, userId: decoded.userId, username: decoded.username }
        : null
    );
    return user ? { userId: user.id, username: user.username } : null;
  } catch (error) {
    if (!(error instanceof jwt.TokenExpiredError)) console.warn('WebSocket token verification failed:', error instanceof Error ? error.message : String(error));
    return null;
  }
};

export { validateApiKey, authenticateToken, generateToken, authenticateWebSocket, JWT_SECRET };
