// ===== utils/discord.js (Enhanced) =====
const axios = require('axios');
const { OAuthToken, User } = require('../models');

/**
 * Exchange authorization code for access and refresh tokens
 */
async function getAccessToken(code) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    scope: 'identify guilds'
  });

  try {
    const response = await axios.post(
      'https://discord.com/api/oauth2/token',
      params,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Discord token exchange error:', error.response?.data || error.message);
    throw new Error('Failed to exchange authorization code for access token');
  }
}

/**
 * Refresh Discord access token using refresh token
 */
async function refreshAccessToken(refresh_token) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: refresh_token
  });

  try {
    const response = await axios.post(
      'https://discord.com/api/oauth2/token',
      params,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Discord token refresh error:', error.response?.data || error.message);
    throw new Error('Failed to refresh Discord access token');
  }
}

/**
 * Get user information from Discord API
 */
async function getUserInfo(accessToken) {
  try {
    const response = await axios.get('https://discord.com/api/users/@me', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    return response.data;
  } catch (error) {
    console.error('Discord user info error:', error.response?.data || error.message);
    
    // If token is invalid, throw specific error for token refresh handling
    if (error.response?.status === 401) {
      throw new Error('INVALID_TOKEN');
    }
    
    throw new Error('Failed to fetch user information from Discord');
  }
}

/**
 * Get user guilds from Discord API
 */
async function getUserGuilds(accessToken) {
  try {
    const response = await axios.get('https://discord.com/api/users/@me/guilds', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    return response.data;
  } catch (error) {
    console.error('Discord guilds fetch error:', error.response?.data || error.message);
    
    // If token is invalid, throw specific error for token refresh handling
    if (error.response?.status === 401) {
      throw new Error('INVALID_TOKEN');
    }
    
    throw new Error('Failed to fetch user guilds from Discord');
  }
}

/**
 * Get guild information using bot token
 */
async function getGuildInfo(guildId, botToken) {
  try {
    const response = await axios.get(`https://discord.com/api/guilds/${guildId}`, {
      headers: {
        'Authorization': `Bot ${botToken}`
      }
    });
    
    return response.data;
  } catch (error) {
    console.error('Discord guild info error:', error.response?.data || error.message);
    throw new Error('Failed to fetch guild information');
  }
}

/**
 * Check if user has admin permissions in guild
 */
function hasAdminPermissions(permissions) {
  const ADMINISTRATOR = 0x8;
  const MANAGE_GUILD = 0x20;
  
  return (permissions & ADMINISTRATOR) === ADMINISTRATOR || 
         (permissions & MANAGE_GUILD) === MANAGE_GUILD;
}

/**
 * Get valid access token for user (with automatic refresh)
 */
async function getValidAccessToken(userId) {
  try {
    // Get the user's current OAuth token from database
    const tokenRecord = await OAuthToken.findOne({
      where: { user_id: userId },
      order: [['created_at', 'DESC']] // Get the most recent token
    });

    if (!tokenRecord) {
      throw new Error('No OAuth token found for user');
    }

    const now = new Date();
    const expiresAt = new Date(tokenRecord.expires_at);

    // If token is still valid (with 5 minute buffer), return it
    if (expiresAt.getTime() - now.getTime() > 5 * 60 * 1000) {
      return tokenRecord.access_token;
    }

    console.log(`🔄 Refreshing Discord token for user ${userId}`);

    // Token is expired or about to expire, refresh it
    const refreshedTokens = await refreshAccessToken(tokenRecord.refresh_token);

    // Calculate new expiration time (Discord tokens expire in 7 days by default)
    const newExpiresAt = new Date(Date.now() + (refreshedTokens.expires_in * 1000));

    // Update the token record in database
    await tokenRecord.update({
      access_token: refreshedTokens.access_token,
      refresh_token: refreshedTokens.refresh_token || tokenRecord.refresh_token,
      expires_at: newExpiresAt,
      scope: refreshedTokens.scope || tokenRecord.scope
    });

    console.log(`✅ Discord token refreshed successfully for user ${userId}`);
    return refreshedTokens.access_token;

  } catch (error) {
    console.error(`❌ Failed to get valid access token for user ${userId}:`, error.message);
    
    // If refresh fails, the user needs to re-authenticate
    if (error.message.includes('refresh') || error.message === 'INVALID_TOKEN') {
      throw new Error('TOKEN_REFRESH_FAILED');
    }
    
    throw error;
  }
}

/**
 * Store OAuth tokens in database
 */
async function storeOAuthTokens(userId, tokens) {
  try {
    // Calculate expiration time (Discord tokens typically expire in 7 days)
    const expiresAt = new Date(Date.now() + (tokens.expires_in * 1000));

    // Delete old tokens for this user
    await OAuthToken.destroy({
      where: { user_id: userId }
    });

    // Create new token record
    const tokenRecord = await OAuthToken.create({
      user_id: userId,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      token_type: tokens.token_type || 'Bearer',
      scope: tokens.scope,
      expires_at: expiresAt
    });

    console.log(`💾 OAuth tokens stored for user ${userId}`);
    return tokenRecord;

  } catch (error) {
    console.error('Failed to store OAuth tokens:', error);
    throw new Error('Failed to store OAuth tokens');
  }
}

/**
 * Revoke Discord OAuth token
 */
async function revokeAccessToken(accessToken) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    token: accessToken
  });

  try {
    await axios.post(
      'https://discord.com/api/oauth2/token/revoke',
      params,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    console.log('✅ Discord token revoked successfully');
    return true;
  } catch (error) {
    console.error('Discord token revocation error:', error.response?.data || error.message);
    // Don't throw error here as token might already be invalid
    return false;
  }
}

/**
 * Validate and refresh token if needed for API calls
 */
async function makeAuthenticatedRequest(userId, apiCall) {
  try {
    // Get valid access token (will refresh if needed)
    const accessToken = await getValidAccessToken(userId);
    
    // Execute the API call with the valid token
    return await apiCall(accessToken);
    
  } catch (error) {
    if (error.message === 'TOKEN_REFRESH_FAILED') {
      throw new Error('User needs to re-authenticate with Discord');
    }
    throw error;
  }
}

module.exports = { 
  getAccessToken, 
  refreshAccessToken,
  getUserInfo,
  getUserGuilds,
  getGuildInfo,
  hasAdminPermissions,
  getValidAccessToken,
  storeOAuthTokens,
  revokeAccessToken,
  makeAuthenticatedRequest
};