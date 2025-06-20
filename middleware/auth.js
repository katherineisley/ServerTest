// ===== middleware/auth.js =====
// 🔥 NEW: Enhanced authentication middleware with auto-refresh
const jwt = require('jsonwebtoken');
const { refreshAccessToken, getUserInfo } = require('../utils/discord');

// Enhanced middleware that handles token refresh automatically
const authenticateTokenWithRefresh = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Try to verify the current token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (jwtError) {
    // If token is expired, attempt refresh
    if (jwtError.name === 'TokenExpiredError') {
      try {
        // Decode expired token to get refresh token
        const expiredDecoded = jwt.decode(token);
        
        if (!expiredDecoded || !expiredDecoded.refreshToken) {
          return res.status(401).json({ 
            error: 'Token expired and no refresh token available',
            shouldReauth: true 
          });
        }

        // Attempt to refresh the Discord token
        const newTokens = await refreshAccessToken(expiredDecoded.refreshToken);
        const userInfo = await getUserInfo(newTokens.access_token);
        
        // Create new JWT payload
        const newJwtPayload = {
          discordId: userInfo.id,
          username: userInfo.username,
          discriminator: userInfo.discriminator,
          avatar: userInfo.avatar,
          email: userInfo.email,
          verified: userInfo.verified,
          accessToken: newTokens.access_token,
          refreshToken: newTokens.refresh_token || expiredDecoded.refreshToken,
          iat: Math.floor(Date.now() / 1000)
        };

        // Sign new JWT token
        const newJwtToken = jwt.sign(
          newJwtPayload, 
          process.env.JWT_SECRET, 
          { 
            expiresIn: process.env.JWT_EXPIRES_IN || '24h',
            issuer: 'discord-oauth-backend'
          }
        );

        // Set the new token in response header for frontend to use
        res.setHeader('X-New-Token', newJwtToken);
        
        req.user = newJwtPayload;
        next();
        
      } catch (refreshError) {
        console.error('Auto-refresh failed:', refreshError);
        return res.status(401).json({ 
          error: 'Token refresh failed',
          shouldReauth: true 
        });
      }
    } else {
      return res.status(403).json({ error: 'Invalid token' });
    }
  }
};

// Original simple middleware (for backward compatibility)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

module.exports = { 
  authenticateToken, 
  authenticateTokenWithRefresh 
};