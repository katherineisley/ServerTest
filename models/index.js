// ===== models/index.js =====
const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

// Database connection
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER, 
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    timezone: '+00:00',
    define: {
      charset: 'utf8mb4',
      collate: 'utf8mb4_unicode_ci'
    }
  }
);

// User model
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  discord_id: {
    type: DataTypes.STRING(20),
    unique: true,
    allowNull: false
  },
  username: {
    type: DataTypes.STRING(32),
    allowNull: false
  },
  discriminator: {
    type: DataTypes.STRING(4),
    allowNull: true
  },
  avatar: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  email: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  tableName: 'users',
  underscored: true,
  indexes: [
    { fields: ['discord_id'] },
    { fields: ['email'] }
  ]
});

// OAuth Tokens model
const OAuthToken = sequelize.define('OAuthToken', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: User,
      key: 'id'
    }
  },
  access_token: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  refresh_token: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  token_type: {
    type: DataTypes.STRING(20),
    defaultValue: 'Bearer'
  },
  scope: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  tableName: 'oauth_tokens',
  underscored: true,
  indexes: [
    { fields: ['user_id'] },
    { fields: ['expires_at'] }
  ]
});

// User Sessions model
const UserSession = sequelize.define('UserSession', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: User,
      key: 'id'
    }
  },
  jwt_token_id: {
    type: DataTypes.STRING(255),
    unique: true,
    allowNull: false
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  last_accessed: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  ip_address: {
    type: DataTypes.STRING(45),
    allowNull: true
  },
  user_agent: {
    type: DataTypes.TEXT,
    allowNull: true
  }
}, {
  tableName: 'user_sessions',
  underscored: true,
  timestamps: true,
  indexes: [
    { fields: ['user_id'] },
    { fields: ['jwt_token_id'] },
    { fields: ['expires_at'] },
    { fields: ['is_active'] }
  ]
});

// User Guilds model (optional)
const UserGuild = sequelize.define('UserGuild', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: User,
      key: 'id'
    }
  },
  guild_id: {
    type: DataTypes.STRING(20),
    allowNull: false
  },
  guild_name: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  guild_icon: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  permissions: {
    type: DataTypes.BIGINT,
    allowNull: false
  },
  owner: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  last_synced: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'user_guilds',
  underscored: true,
  indexes: [
    { 
      unique: true,
      fields: ['user_id', 'guild_id'] 
    },
    { fields: ['user_id'] },
    { fields: ['guild_id'] },
    { fields: ['permissions'] }
  ]
});

// Define associations
User.hasMany(OAuthToken, { foreignKey: 'user_id', onDelete: 'CASCADE' });
OAuthToken.belongsTo(User, { foreignKey: 'user_id' });

User.hasMany(UserSession, { foreignKey: 'user_id', onDelete: 'CASCADE' });
UserSession.belongsTo(User, { foreignKey: 'user_id' });

User.hasMany(UserGuild, { foreignKey: 'user_id', onDelete: 'CASCADE' });
UserGuild.belongsTo(User, { foreignKey: 'user_id' });

// Database connection test and sync
const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully');
    
    // Sync models in development (create tables if they don't exist)
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
      console.log('📋 Database models synchronized');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Unable to connect to database:', error);
    return false;
  }
};

// Cleanup function for expired data
const cleanupExpiredData = async () => {
  try {
    const now = new Date();
    
    // Deactivate expired sessions
    await UserSession.update(
      { is_active: false },
      { 
        where: {
          expires_at: { [Sequelize.Op.lte]: now },
          is_active: true
        }
      }
    );
    
    // Delete old expired sessions (older than 7 days)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await UserSession.destroy({
      where: {
        expires_at: { [Sequelize.Op.lte]: sevenDaysAgo }
      }
    });
    
    // Delete expired OAuth tokens
    await OAuthToken.destroy({
      where: {
        expires_at: { [Sequelize.Op.lte]: now }
      }
    });
    
    console.log('🧹 Cleanup completed successfully');
  } catch (error) {
    console.error('❌ Cleanup failed:', error);
  }
};

module.exports = {
  sequelize,
  User,
  OAuthToken,
  UserSession,
  UserGuild,
  connectDB,
  cleanupExpiredData
};