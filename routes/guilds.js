// ===== routes/guilds.js (Enhanced) =====
const express = require('express');
const { 
  getUserGuilds, 
  getGuildInfo, 
  hasAdminPermissions, 
  makeAuthenticatedRequest 
} = require('../utils/discord');
const { User, UserSession, UserGuild } = require('../models');

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
    const jwt = require('jsonwebtoken');
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
 * Get user's guilds with automatic token refresh
 */
router.get('/my-guilds', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Use makeAuthenticatedRequest to handle token refresh automatically
    const userGuilds = await makeAuthenticatedRequest(user.id, async (accessToken) => {
      return await getUserGuilds(accessToken);
    });

    // Process and return guild data
    const processedGuilds = userGuilds.map(guild => ({
      id: guild.id,
      name: guild.name,
      icon: guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png` : null,
      owner: guild.owner,
      permissions: guild.permissions,
      hasAdminPerms: hasAdminPermissions(guild.permissions),
      features: guild.features || []
    }));

    // Update cached guild data in database
    await updateUserGuildsCache(user.id, userGuilds);

    res.json({ 
      guilds: processedGuilds,
      totalCount: processedGuilds.length,
      adminGuildsCount: processedGuilds.filter(g => g.hasAdminPerms).length
    });

  } catch (error) {
    console.error('Error fetching user guilds:', error);

    if (error.message === 'User needs to re-authenticate with Discord') {
      return res.status(401).json({ 
        error: 'Discord authentication expired. Please log in again.',
        requiresReauth: true
      });
    }

    res.status(500).json({ error: 'Failed to fetch guilds' });
  }
});

/**
 * Get user's admin guilds only
 */
router.get('/admin-guilds', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Use makeAuthenticatedRequest to handle token refresh automatically
    const userGuilds = await makeAuthenticatedRequest(user.id, async (accessToken) => {
      return await getUserGuilds(accessToken);
    });
    
    // Filter guilds where user has admin permissions
    const adminGuilds = userGuilds.filter(guild => hasAdminPermissions(guild.permissions));
    
    // Optionally, fetch additional guild info for each admin guild using bot token
    const detailedGuilds = await Promise.all(
      adminGuilds.map(async (guild) => {
        let guildInfo = {
          id: guild.id,
          name: guild.name,
          icon: guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png` : null,
          owner: guild.owner,
          permissions: guild.permissions,
          features: guild.features || []
        };

        // Try to get additional info using bot token (if available)
        if (process.env.DISCORD_BOT_TOKEN) {
          try {
            const botGuildInfo = await getGuildInfo(guild.id, process.env.DISCORD_BOT_TOKEN);
            guildInfo = {
              ...guildInfo,
              memberCount: botGuildInfo.approximate_member_count,
              description: botGuildInfo.description,
              banner: botGuildInfo.banner ? `https://cdn.discordapp.com/banners/${guild.id}/${botGuildInfo.banner}.png` : null,
              verificationLevel: botGuildInfo.verification_level,
              boostLevel: botGuildInfo.premium_tier,
              boostCount: botGuildInfo.premium_subscription_count
            };
          } catch (error) {
            console.warn(`Could not fetch bot info for guild ${guild.id}:`, error.message);
            // Guild info without bot data is still valid
          }
        }

        return guildInfo;
      })
    );

    // Update cached guild data
    await updateUserGuildsCache(user.id, userGuilds);

    res.json({ 
      guilds: detailedGuilds,
      totalCount: detailedGuilds.length
    });

  } catch (error) {
    console.error('Error fetching admin guilds:', error);

    if (error.message === 'User needs to re-authenticate with Discord') {
      return res.status(401).json({ 
        error: 'Discord authentication expired. Please log in again.',
        requiresReauth: true
      });
    }

    res.status(500).json({ error: 'Failed to fetch admin guilds' });
  }
});

/**
 * Get specific guild information (user must be admin)
 */
router.get('/guild/:guildId', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { guildId } = req.params;

    // First check if user has access to this guild
    const userGuilds = await makeAuthenticatedRequest(user.id, async (accessToken) => {
      return await getUserGuilds(accessToken);
    });

    const guild = userGuilds.find(g => g.id === guildId);
    
    if (!guild) {
      return res.status(404).json({ error: 'Guild not found or user not a member' });
    }

    if (!hasAdminPermissions(guild.permissions)) {
      return res.status(403).json({ error: 'Insufficient permissions for this guild' });
    }

    // Get detailed guild information using bot token
    let detailedGuildInfo = {
      id: guild.id,
      name: guild.name,
      icon: guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png` : null,
      owner: guild.owner,
      permissions: guild.permissions,
      features: guild.features || []
    };

    if (process.env.DISCORD_BOT_TOKEN) {
      try {
        const botGuildInfo = await getGuildInfo(guildId, process.env.DISCORD_BOT_TOKEN);
        detailedGuildInfo = {
          ...detailedGuildInfo,
          description: botGuildInfo.description,
          memberCount: botGuildInfo.approximate_member_count,
          presenceCount: botGuildInfo.approximate_presence_count,
          banner: botGuildInfo.banner ? `https://cdn.discordapp.com/banners/${guildId}/${botGuildInfo.banner}.png` : null,
          splash: botGuildInfo.splash ? `https://cdn.discordapp.com/splashes/${guildId}/${botGuildInfo.splash}.png` : null,
          verificationLevel: botGuildInfo.verification_level,
          explicitContentFilter: botGuildInfo.explicit_content_filter,
          defaultMessageNotifications: botGuildInfo.default_message_notifications,
          boostLevel: botGuildInfo.premium_tier,
          boostCount: botGuildInfo.premium_subscription_count,
          maxMembers: botGuildInfo.max_members,
          maxPresences: botGuildInfo.max_presences,
          vanityUrlCode: botGuildInfo.vanity_url_code,
          preferredLocale: botGuildInfo.preferred_locale,
          nsfw: botGuildInfo.nsfw,
          nsfwLevel: botGuildInfo.nsfw_level
        };
      } catch (error) {
        console.warn(`Could not fetch detailed guild info for ${guildId}:`, error.message);
      }
    }

    res.json({ guild: detailedGuildInfo });

  } catch (error) {
    console.error('Error fetching guild info:', error);

    if (error.message === 'User needs to re-authenticate with Discord') {
      return res.status(401).json({ 
        error: 'Discord authentication expired. Please log in again.',
        requiresReauth: true
      });
    }

    res.status(500).json({ error: 'Failed to fetch guild information' });
  }
});

/**
 * Get cached guild data from database
 */
router.get('/cached-guilds', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    const cachedGuilds = await UserGuild.findAll({
      where: { user_id: user.id },
      order: [['last_synced', 'DESC']]
    });

    const processedGuilds = cachedGuilds.map(guild => ({
      id: guild.guild_id,
      name: guild.guild_name,
      icon: guild.guild_icon ? `https://cdn.discordapp.com/icons/${guild.guild_id}/${guild.guild_icon}.png` : null,
      permissions: guild.permissions,
      owner: guild.owner,
      hasAdminPerms: hasAdminPermissions(guild.permissions),
      lastSynced: guild.last_synced
    }));

    res.json({ 
      guilds: processedGuilds,
      totalCount: processedGuilds.length,
      adminGuildsCount: processedGuilds.filter(g => g.hasAdminPerms).length,
      lastSync: cachedGuilds.length > 0 ? cachedGuilds[0].last_synced : null
    });

  } catch (error) {
    console.error('Error fetching cached guilds:', error);
    res.status(500).json({ error: 'Failed to fetch cached guild data' });
  }
});

/**
 * Force refresh guild cache
 */
router.post('/refresh-guilds', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Fetch fresh guild data from Discord
    const userGuilds = await makeAuthenticatedRequest(user.id, async (accessToken) => {
      return await getUserGuilds(accessToken);
    });

    // Update cache
    await updateUserGuildsCache(user.id, userGuilds);

    const processedGuilds = userGuilds.map(guild => ({
      id: guild.id,
      name: guild.name,
      icon: guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png` : null,
      owner: guild.owner,
      permissions: guild.permissions,
      hasAdminPerms: hasAdminPermissions(guild.permissions),
      features: guild.features || []
    }));

    res.json({ 
      success: true,
      message: 'Guild cache refreshed successfully',
      guilds: processedGuilds,
      refreshedAt: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error refreshing guild cache:', error);

    if (error.message === 'User needs to re-authenticate with Discord') {
      return res.status(401).json({ 
        error: 'Discord authentication expired. Please log in again.',
        requiresReauth: true
      });
    }

    res.status(500).json({ error: 'Failed to refresh guild cache' });
  }
});

/**
 * Helper function to update user guilds cache in database
 */
async function updateUserGuildsCache(userId, guilds) {
  try {
    // Remove old cached guilds for this user
    await UserGuild.destroy({ where: { user_id: userId } });

    // Insert fresh guild data
    const guildRecords = guilds.map(guild => ({
      user_id: userId,
      guild_id: guild.id,
      guild_name: guild.name,
      guild_icon: guild.icon,
      permissions: guild.permissions,
      owner: guild.owner || false,
      last_synced: new Date()
    }));

    if (guildRecords.length > 0) {
      await UserGuild.bulkCreate(guildRecords);
      console.log(`💾 Updated guild cache for user ${userId}: ${guildRecords.length} guilds`);
    }

  } catch (error) {
    console.error('Error updating guild cache:', error);
    // Don't throw error here as main functionality should still work
  }
}

module.exports = router;