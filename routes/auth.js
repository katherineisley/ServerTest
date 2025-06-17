const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { getAccessToken, refreshAccessToken, getUserInfo, getUserGuilds } = require('../utils/discord');
const User = require('../models/User');

const router = express.Router();

router.use(cookieParser());

// Step 1: Redirect to Discord
router.get('/discord', (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&response_type=code&scope=identify guilds`;
  res.redirect(url);
});

// Step 2: Handle callback
router.get('/discord/callback', async (req, res) => {
  try {
    const tokens = await getAccessToken(req.query.code);
    const userInfo = await getUserInfo(tokens.access_token);

    // Upsert user
    const [user] = await User.findOrCreate({
      where: { discordId: userInfo.id },
      defaults: {
        username: userInfo.username,
        avatar: userInfo.avatar,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      }
    });

    // Update tokens
    await user.update({
      username: userInfo.username,
      avatar: userInfo.avatar,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token
    });

    // JWT + httpOnly secure cookie
    const token = jwt.sign({ id: user.discordId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'Strict',
      maxAge: 3600000
    });

    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('OAuth Error');
  }
});

// Middleware to verify JWT in cookie
async function verifyUser(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('No token');

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ where: { discordId: payload.id } });
    if (!user) return res.status(404).send('User not found');
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).send('Invalid token');
  }
}

// Step 3: Protected route
router.get('/me', verifyUser, async (req, res) => {
  try {
    let guilds;
    try {
      guilds = await getUserGuilds(req.user.accessToken);
    } catch {
      // token expired, refresh it
      const tokens = await refreshAccessToken(req.user.refreshToken);
      await req.user.update({
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      });
      guilds = await getUserGuilds(tokens.access_token);
    }

    // Validate permissions (show only servers where user has MANAGE_GUILD or ADMIN)
    const filteredGuilds = guilds.filter(g => (g.permissions & 0x20) || (g.permissions & 0x8));

    res.json({
      user: {
        id: req.user.discordId,
        username: req.user.username,
        avatar: req.user.avatar
      },
      guilds: filteredGuilds
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
