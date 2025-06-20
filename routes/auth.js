// ===== routes/auth.js =====
const express = require('express');
const jwt = require('jsonwebtoken');
const { getAccessToken, getUserInfo, refreshAccessToken } = require('../utils/discord');

const router = express.Router();

router.get('/discord', (req, res) => {
  const state = Math.random().toString(36).substring(2, 15);
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?` +
    `client_id=${process.env.DISCORD_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&` +
    `response_type=code&` +
    `scope=identify guilds&` + 
    `state=${state}`;
  
  res.redirect(discordAuthUrl);
});

// Step 2: Handle Discord callback and redirect to frontend
router.get('/discord/callback', async (req, res) => {
  const { code, error, state } = req.query;

  // Handle OAuth errors
  if (error) {
    console.error('Discord OAuth error:', error);
    return res.redirect(`${process.env.FRONTEND_URL}?error=oauth_failed`);
  }

  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}?error=no_code`);
  }

  try {
    // Exchange code for access token
    const tokens = await getAccessToken(code);
    
    // Get user information
    const userInfo = await getUserInfo(tokens.access_token);
    
    // Create JWT payload - NOW INCLUDING REFRESH TOKEN
    const jwtPayload = {
      discordId: userInfo.id,
      username: userInfo.username,
      discriminator: userInfo.discriminator,
      avatar: userInfo.avatar,
      email: userInfo.email,
      verified: userInfo.verified,
      accessToken: tokens.access_token, // Store access token
      refreshToken: tokens.refresh_token, // 🔥 NEW: Store refresh token
      iat: Math.floor(Date.now() / 1000)
    };

    // Sign JWT token
    const jwtToken = jwt.sign(
      jwtPayload, 
      process.env.JWT_SECRET, 
      { 
        expiresIn: process.env.JWT_EXPIRES_IN || '24h',
        issuer: 'discord-oauth-backend'
      }
    );

    // Redirect back to frontend with token
    res.redirect(`${process.env.FRONTEND_URL}?token=${jwtToken}`);

  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
  }
});

// 🔥 NEW: Token refresh endpoint
router.post('/refresh', async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    // Try to verify the token (this will throw if expired)
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      // If we get here, token is still valid - no refresh needed
      return res.json({ 
        refreshed: false, 
        token: token,
        message: 'Token is still valid' 
      });
    } catch (jwtError) {
      // Token is expired or invalid, try to decode without verification to get refresh token
      if (jwtError.name !== 'TokenExpiredError') {
        return res.status(401).json({ error: 'Invalid token format' });
      }
      
      // Decode expired token to get refresh_token
      decoded = jwt.decode(token);
      if (!decoded || !decoded.refreshToken) {
        return res.status(401).json({ error: 'No refresh token available' });
      }
    }

    // Use Discord refresh token to get new access token
    const newTokens = await refreshAccessToken(decoded.refreshToken);
    
    // Get updated user info with new access token
    const userInfo = await getUserInfo(newTokens.access_token);
    
    // Create new JWT payload with refreshed data
    const newJwtPayload = {
      discordId: userInfo.id,
      username: userInfo.username,
      discriminator: userInfo.discriminator,
      avatar: userInfo.avatar,
      email: userInfo.email,
      verified: userInfo.verified,
      accessToken: newTokens.access_token,
      refreshToken: newTokens.refresh_token || decoded.refreshToken, // Use new refresh token if provided
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

    res.json({ 
      refreshed: true, 
      token: newJwtToken,
      user: newJwtPayload,
      expiresAt: new Date((jwt.decode(newJwtToken).exp) * 1000).toISOString()
    });

  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(401).json({ 
      error: 'Token refresh failed',
      message: err.message 
    });
  }
});

// Token verification endpoint (updated to handle refresh)
router.post('/verify', async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ 
      valid: true, 
      user: decoded,
      expiresAt: new Date(decoded.exp * 1000).toISOString()
    });
  } catch (err) {
    // 🔥 NEW: Suggest refresh for expired tokens
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        valid: false, 
        error: 'Token expired',
        shouldRefresh: true // Signal frontend to attempt refresh
      });
    }
    
    res.status(401).json({ 
      valid: false, 
      error: 'Invalid token' 
    });
  }
});

module.exports = router;