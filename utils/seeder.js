const User = require('../models/User');
const bcrypt = require('bcryptjs');

const seedAdmin = async () => {
  try {
    const adminEmail = (process.env.ADMIN_EMAIL || 'admin@cybershield15043001.com').toLowerCase().trim();
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin@15043001';
    const adminUsername = process.env.ADMIN_USERNAME || 'CyberShieldAdmin';

    // Hash password ONCE using bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);

    // Look for existing admin by role or email
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
      console.log(`[+] Admin user updated successfully: ${adminEmail}`);
    } else {
      await User.create({
        username: adminUsername,
        email: adminEmail,
        password: adminPassword, // Hashed once by UserSchema pre('save') hook
        role: 'admin',
        isVerified: true
      });
      console.log(`[+] Admin user created successfully: ${adminEmail}`);
    }
  } catch (error) {
    console.warn('[-] Admin seeder warning:', error.message);
  }
};

module.exports = { seedAdmin };
