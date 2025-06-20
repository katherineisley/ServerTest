// ===== routes/auth.js (Enhanced) =====
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { 
  getAccessToken, 
  getUserInfo, 
  storeOAuthTokens,
  revokeAccessToken,
  getValidAccessToken 
} = require('../utils/discord');
const { User, UserSession, OAuthToken } = require('../models');

const router = express.Router();

/**
 * Middleware to authenticate JWT token and get user
 */
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if session is still active in database
    const session = await UserSession.findOne({
      where: {
        jwt_token_id: decoded.jti,
        is_active: true,
        expires_at: { [require('sequelize').Op.gt]: new Date() }
      },
      include: [{ model: User }]
    });

    if (!session) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    // Update last accessed time
    await session.update({ last_accessed: new Date() });

    req.user = session.User;
    req.session = session;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

/**
 * Step 1: Redirect to Discord OAuth
 */
router.get('/discord', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?` +
    `client_id=${process.env.DISCORD_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&` +
    `response_type=code&` +
    `scope=identify guilds&` + 
    `state=${state}`;
  
  res.redirect(discordAuthUrl);
});

/**
 * Step 2: Handle Discord callback and create session
 */
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
    
    // Get user information from Discord
    const userInfo = await getUserInfo(tokens.access_token);
    
    // Find or create user in database
    let user = await User.findOne({ where: { discord_id: userInfo.id } });
    
    if (!user) {
      // Create new user
      user = await User.create({
        discord_id: userInfo.id,
        username: userInfo.username,
        discriminator: userInfo.discriminator,
        avatar: userInfo.avatar,
        email: userInfo.email,
        verified: userInfo.verified || false
      });
      console.log(`👤 New user created: ${userInfo.username} (${userInfo.id})`);
    } else {
      // Update existing user information
      await user.update({
        username: userInfo.username,
        discriminator: userInfo.discriminator,
        avatar: userInfo.avatar,
        email: userInfo.email,
        verified: userInfo.verified || false
      });
      console.log(`🔄 User updated: ${userInfo.username} (${userInfo.id})`);
    }

    // Store OAuth tokens in database
    await storeOAuthTokens(user.id, tokens);

    // Generate unique JWT token ID
    const jti = crypto.randomUUID();
    const sessionExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create JWT payload
    const jwtPayload = {
      jti: jti,
      sub: user.discord_id,
      userId: user.id,
      username: user.username,
      avatar: user.avatar,
      email: user.email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(sessionExpiresAt.getTime() / 1000)
    };

    // Sign JWT token
    const jwtToken = jwt.sign(jwtPayload, process.env.JWT_SECRET);

    // Create session record in database
    await UserSession.create({
      user_id: user.id,
      jwt_token_id: jti,
      expires_at: sessionExpiresAt,
      ip_address: req.ip || req.connection.remoteAddress,
      user_agent: req.get('User-Agent')
    });

    console.log(`✅ Session created for user ${user.username}`);

    // Redirect back to frontend with token
    res.redirect(`${process.env.FRONTEND_URL}?token=${jwtToken}`);

  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
  }
});

/**
 * Token verification and refresh endpoint
 */
router.post('/verify', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const session = req.session;

    // Check if Discord token needs refresh and get valid token
    let validAccessToken;
    try {
      validAccessToken = await getValidAccessToken(user.id);
    } catch (error) {
      if (error.message === 'TOKEN_REFRESH_FAILED') {
        // Mark session as expired and return error
        await session.update({ is_active: false });
        return res.status(401).json({ 
          valid: false, 
          error: 'Discord token expired. Please re-authenticate.',
          requiresReauth: true
        });
      }
      throw error;
    }

    // Return user data
    res.json({ 
      valid: true, 
      user: {
        id: user.id,
        discordId: user.discord_id,
        username: user.username,
        discriminator: user.discriminator,
        avatar: user.avatar,
        email: user.email,
        verified: user.verified
      },
      session: {
        expiresAt: session.expires_at.toISOString(),
        lastAccessed: session.last_accessed.toISOString()
      }
    });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(500).json({ 
      valid: false, 
      error: 'Internal server error during verification' 
    });
  }
});

/**
 * Refresh JWT token endpoint (extend session)
 */
router.post('/refresh', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const currentSession = req.session;

    // Generate new JWT token with extended expiration
    const newJti = crypto.randomUUID();
    const newSessionExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const jwtPayload = {
      jti: newJti,
      sub: user.discord_id,
      userId: user.id,
      username: user.username,
      avatar: user.avatar,
      email: user.email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(newSessionExpiresAt.getTime() / 1000)
    };

    const newJwtToken = jwt.sign(jwtPayload, process.env.JWT_SECRET);

    // Deactivate old session
    await currentSession.update({ is_active: false });

    // Create new session
    await UserSession.create({
      user_id: user.id,
      jwt_token_id: newJti,
      expires_at: newSessionExpiresAt,
      ip_address: req.ip || req.connection.remoteAddress,
      user_agent: req.get('User-Agent')
    });

    console.log(`🔄 Session refreshed for user ${user.username}`);

    res.json({
      success: true,
      token: newJwtToken,
      expiresAt: newSessionExpiresAt.toISOString()
    });

  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(500).json({ 
      error: 'Failed to refresh token' 
    });
  }
});

/**
 * Logout endpoint - revoke session and Discord token
 */
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const session = req.session;

    // Deactivate current session
    await session.update({ is_active: false });

    //Optionally revoke Discord OAuth token (uncomment if desired)
    try {
      const validAccessToken = await getValidAccessToken(user.id);
      await revokeAccessToken(validAccessToken);
    } catch (error) {
      console.warn('Could not revoke Discord token:', error.message);
    }

    console.log(`👋 User ${user.username} logged out`);

    res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });

  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ 
      error: 'Failed to logout' 
    });
  }
});

/**
 * Get current user profile
 */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Get OAuth token info
    const tokenInfo = await OAuthToken.findOne({
      where: { user_id: user.id },
      order: [['created_at', 'DESC']]
    });

    res.json({
      user: {
        id: user.id,
        discordId: user.discord_id,
        username: user.username,
        discriminator: user.discriminator,
        avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png` : null,
        email: user.email,
        verified: user.verified,
        createdAt: user.created_at,
        updatedAt: user.updated_at
      },
      tokenInfo: tokenInfo ? {
        scope: tokenInfo.scope,
        expiresAt: tokenInfo.expires_at,
        tokenType: tokenInfo.token_type
      } : null
    });

  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ 
      error: 'Failed to get user profile' 
    });
  }
});

/**
 * Delete account endpoint
 */
router.delete('/account', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Revoke Discord token before deletion
    try {
      const validAccessToken = await getValidAccessToken(user.id);
      await revokeAccessToken(validAccessToken);
    } catch (error) {
      console.warn('Could not revoke Discord token during account deletion:', error.message);
    }

    // Delete user (cascades to sessions and tokens due to foreign key constraints)
    await user.destroy();

    console.log(`🗑️ Account deleted for user ${user.username}`);

    res.json({ 
      success: true, 
      message: 'Account deleted successfully' 
    });

  } catch (err) {
    console.error('Account deletion error:', err);
    res.status(500).json({ 
      error: 'Failed to delete account' 
    });
  }
});

/**
 * Get user sessions
 */
router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    const sessions = await UserSession.findAll({
      where: { 
        user_id: user.id,
        is_active: true,
        expires_at: { [require('sequelize').Op.gt]: new Date() }
      },
      order: [['last_accessed', 'DESC']],
      attributes: ['id', 'jwt_token_id', 'created_at', 'last_accessed', 'expires_at', 'ip_address', 'user_agent']
    });

    res.json({ 
      sessions: sessions.map(session => ({
        id: session.id,
        isCurrentSession: session.jwt_token_id === req.session.jwt_token_id,
        createdAt: session.created_at,
        lastAccessed: session.last_accessed,
        expiresAt: session.expires_at,
        ipAddress: session.ip_address,
        userAgent: session.user_agent
      }))
    });

  } catch (err) {
    console.error('Get sessions error:', err);
    res.status(500).json({ 
      error: 'Failed to get sessions' 
    });
  }
});

/**
 * Revoke specific session
 */
router.delete('/sessions/:sessionId', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { sessionId } = req.params;

    const session = await UserSession.findOne({
      where: { 
        id: sessionId,
        user_id: user.id,
        is_active: true
      }
    });

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Don't allow user to revoke their current session via this endpoint
    if (session.jwt_token_id === req.session.jwt_token_id) {
      return res.status(400).json({ error: 'Cannot revoke current session. Use logout endpoint instead.' });
    }

    await session.update({ is_active: false });

    res.json({ 
      success: true, 
      message: 'Session revoked successfully' 
    });

  } catch (err) {
    console.error('Revoke session error:', err);
    res.status(500).json({ 
      error: 'Failed to revoke session' 
    });
  }
});

module.exports = router;