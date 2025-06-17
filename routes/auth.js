// ===== routes/auth.js =====
const express = require('express');
const jwt = require('jsonwebtoken');
const { getAccessToken, getUserInfo } = require('../utils/discord');

const router = express.Router();

// Step 1: Redirect to Discord OAuth2
router.get('/discord', (req, res) => {
  const state = Math.random().toString(36).substring(2, 15);
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?` +
    `client_id=${process.env.DISCORD_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&` +
    `response_type=code&` +
    `scope=identify&` +
    `state=${state}`;
  
  res.redirect(discordAuthUrl);
});

// Step 2: Handle Discord callback and redirect to frontend
router.get('/discord/callback', async (req, res) => {
  const { code, error, state } = req.query;

  // Handle OAuth errors
  if (error) {
    console.error('Discord OAuth error:', error);
    return res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
  }

  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_code`);
  }

  try {
    // Exchange code for access token
    const tokens = await getAccessToken(code);
    
    // Get user information
    const userInfo = await getUserInfo(tokens.access_token);
    
    // Create JWT payload
    const jwtPayload = {
      discordId: userInfo.id,
      username: userInfo.username,
      discriminator: userInfo.discriminator,
      avatar: userInfo.avatar,
      email: userInfo.email,
      verified: userInfo.verified,
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
    res.redirect(`${process.env.FRONTEND_URL}/login?token=${jwtToken}`);

  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect(`${process.env.FRONTEND_URL}/login?error=auth_failed`);
  }
});

// Token verification endpoint (optional utility)
router.post('/verify', (req, res) => {
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
    res.status(401).json({ 
      valid: false, 
      error: 'Invalid or expired token' 
    });
  }
});

module.exports = router;
