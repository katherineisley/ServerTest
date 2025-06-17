const axios = require('axios');
const qs = require('querystring');

async function getAccessToken(code) {
  const params = {
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    scope: 'identify guilds'
  };

  const res = await axios.post('https://discord.com/api/oauth2/token', qs.stringify(params), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  return res.data;
}

async function refreshAccessToken(refresh_token) {
  const params = {
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    scope: 'identify guilds'
  };

  const res = await axios.post('https://discord.com/api/oauth2/token', qs.stringify(params), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  return res.data;
}

async function getUserInfo(token) {
  return (await axios.get('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${token}` }
  })).data;
}

async function getUserGuilds(token) {
  return (await axios.get('https://discord.com/api/users/@me/guilds', {
    headers: { Authorization: `Bearer ${token}` }
  })).data;
}

module.exports = { getAccessToken, refreshAccessToken, getUserInfo, getUserGuilds };
