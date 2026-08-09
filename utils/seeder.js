const mongoose = require('mongoose');
const User = require('../models/User');
const bcrypt = require('bcryptjs');

const seedAdmin = async () => {
  try {
    const adminEmail = 'admin@cybershield.io';
    const adminExists = await User.findOne({ email: adminEmail });
    
    if (!adminExists) {
      // Create secure admin user
      await User.create({
        username: 'CyberAdmin',
        email: adminEmail,
        password: 'Admin@123456', // Will be hashed by pre-save hook in User model
        role: 'admin',
        twoFactorEnabled: false
      });
      console.log('[+] Admin user seeded successfully.');
    }
  } catch (error) {
    console.warn('[-] Admin seeder warning:', error.message);
  }
};

module.exports = { seedAdmin };
