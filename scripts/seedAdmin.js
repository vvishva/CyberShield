require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

async function seedAdmin() {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';
    await mongoose.connect(mongoUri);
    console.log('[Seed] Connected to MongoDB');

    const adminEmail = (process.env.ADMIN_EMAIL || 'admin@cybershield15043001.com').toLowerCase().trim();
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin@15043001';
    const adminUsername = process.env.ADMIN_USERNAME || 'CyberShieldAdmin';

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);

    let admin = await User.findOne({ $or: [{ role: 'admin' }, { email: adminEmail }] });

    if (admin) {
      await User.updateOne(
        { _id: admin._id },
        {
          $set: {
            username: adminUsername,
            email: adminEmail,
            password: hashedPassword,
            role: 'admin',
            isVerified: true
          }
        }
      );
      console.log('[Seed] Existing Admin updated successfully:', adminEmail);
    } else {
      admin = await User.create({
        username: adminUsername,
        email: adminEmail,
        password: adminPassword,
        role: 'admin',
        isVerified: true
      });
      console.log('[Seed] Admin user created successfully:', adminEmail);
    }

    console.log('[Seed] Admin login ready:');
    console.log('  Email:', adminEmail);
    console.log('  Password:', adminPassword);

  } catch (error) {
    console.error('[Seed] Error:', error.message);
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) {
  seedAdmin();
}

module.exports = seedAdmin;