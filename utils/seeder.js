const User = require('../models/User');
const bcrypt = require('bcryptjs');

const seedAdmin = async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@cybershield15043001.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin@15043001';
    const adminUsername = process.env.ADMIN_USERNAME || 'CyberShieldAdmin';

    const cleanEmail = adminEmail.toLowerCase().trim();

    // Hash the admin password securely
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);

    // Look for existing admin by role or email
    let admin = await User.findOne({ $or: [{ role: 'admin' }, { email: cleanEmail }] });

    if (admin) {
      admin.username = adminUsername;
      admin.email = cleanEmail;
      admin.password = hashedPassword;
      admin.role = 'admin';
      admin.isVerified = true;
      await admin.save();
      console.log(`[+] Admin user updated successfully: ${admin.email} (Username: ${admin.username})`);
    } else {
      await User.create({
        username: adminUsername,
        email: cleanEmail,
        password: hashedPassword,
        role: 'admin',
        isVerified: true
      });
      console.log(`[+] New Admin user created successfully: ${cleanEmail} (Username: ${adminUsername})`);
    }
  } catch (error) {
    console.warn('[-] Admin seeder warning:', error.message);
  }
};

module.exports = { seedAdmin };
