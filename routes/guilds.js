
const express = require('express');
const jwt = require('jsonwebtoken');
const { getUserGuilds, getGuildInfo, hasAdminPermissions } = require('../utils/discord');

const router = express.Router();

// Middleware to verify JWT token
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

// Get user's admin guilds
router.get('/admin-guilds', authenticateToken, async (req, res) => {
  try {
    // You'll need to store the Discord access token when user logs in
    // For now, we'll fetch guilds using the user's permissions from JWT
    const userGuilds = await getUserGuilds(req.user.accessToken);
    
    // Filter guilds where user has admin permissions
    const adminGuilds = userGuilds.filter(guild => hasAdminPermissions(guild.permissions));
    
    // Optionally, fetch additional guild info for each admin guild
    const detailedGuilds = await Promise.all(
      adminGuilds.map(async (guild) => {
        try {
          const guildInfo = await getGuildInfo(guild.id, process.env.DISCORD_BOT_TOKEN);
          return {
            id: guild.id,
            name: guild.name,
            icon: guild.icon,
            owner: guild.owner,
            permissions: guild.permissions,
            memberCount: guildInfo.approximate_member_count,
            description: guildInfo.description
          };
        } catch (error) {
          // If bot is not in guild, return basic info
          return {
            id: guild.id,
            name: guild.name,
            icon: guild.icon,
            owner: guild.owner,
            permissions: guild.permissions
          };
        }
      })
    );

    res.json({ guilds: detailedGuilds });
  } catch (error) {
    console.error('Error fetching admin guilds:', error);
    res.status(500).json({ error: 'Failed to fetch admin guilds' });
  }
});

// Get specific guild info
router.get('/:guildId', authenticateToken, async (req, res) => {
  try {
    const { guildId } = req.params;
    
    // Verify user has access to this guild
    const userGuilds = await getUserGuilds(req.user.accessToken);
    const userGuild = userGuilds.find(g => g.id === guildId);
    
    if (!userGuild || !hasAdminPermissions(userGuild.permissions)) {
      return res.status(403).json({ error: 'No admin access to this guild' });
    }
    
    const guildInfo = await getGuildInfo(guildId, process.env.DISCORD_BOT_TOKEN);
    
    res.json({
      guild: {
        id: guildInfo.id,
        name: guildInfo.name,
        icon: guildInfo.icon,
        description: guildInfo.description,
        memberCount: guildInfo.approximate_member_count,
        ownerId: guildInfo.owner_id,
        features: guildInfo.features
      }
    });
  } catch (error) {
    console.error('Error fetching guild info:', error);
    res.status(500).json({ error: 'Failed to fetch guild information' });
  }
});

module.exports = router;