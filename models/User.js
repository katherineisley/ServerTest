const { DataTypes } = require('sequelize');
const sequelize = require('../config/sequelize');

const User = sequelize.define('User', {
  discordId: { type: DataTypes.STRING, unique: true },
  username: DataTypes.STRING,
  avatar: DataTypes.STRING,
  accessToken: DataTypes.TEXT,
  refreshToken: DataTypes.TEXT
});

module.exports = User;
