// ===== utils/discord.js =====
const axios = require('axios');

async function getAccessToken(code) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    scope: 'identify'
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
    throw new Error('Failed to fetch user information from Discord');
  }
}

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
    throw new Error('Failed to fetch user guilds from Discord');
  }
}

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

// Check if user has admin permissions in guild
function hasAdminPermissions(permissions) {
  const ADMINISTRATOR = 0x8;
  const MANAGE_GUILD = 0x20;
  
  return (permissions & ADMINISTRATOR) === ADMINISTRATOR || 
         (permissions & MANAGE_GUILD) === MANAGE_GUILD;
}

module.exports = { 
  getAccessToken, 
  getUserInfo,
  getUserGuilds,
  getGuildInfo,
  hasAdminPermissions
};