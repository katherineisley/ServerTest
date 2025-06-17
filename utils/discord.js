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

module.exports = { 
  getAccessToken, 
  getUserInfo 
};