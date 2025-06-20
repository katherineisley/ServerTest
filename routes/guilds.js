// ===== routes/guilds.js =====
const express = require('express');
const { getUserGuilds, getGuildInfo, hasAdminPermissions } = require('../utils/discord');
// 🔥 UPDATED: Use the new middleware with auto-refresh
const { authenticateTokenWithRefresh } = require('../middleware/auth');

const router = express.Router();

// Get user's admin guilds - now with auto token refresh!
router.get('/admin-guilds', authenticateTokenWithRefresh, async (req, res) => {
  try {
    // The middleware handles token refresh automatically, so req.user.accessToken is always fresh
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

module.exports = router;