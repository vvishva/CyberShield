/**
 * CyberShield — Admin Account Management & Password Reset Script
 *
 * Updates or creates the CyberShield Admin account in MongoDB with a custom Email, Password, and Username.
 *
 * Usage:
 *   node scripts/updateAdmin.js <email> <password> [username]
 *
 * Examples:
 *   node scripts/updateAdmin.js admin@cybershield.io SuperSecret123
 *   node scripts/updateAdmin.js vishva.admin@gmail.com AdminPass2026 VishvaAdmin
 */

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6, select: false },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  avatar: { type: String, default: 'avatar-cyber-1.png' },
  isVerified: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

async function updateAdmin() {
  const args = process.argv.slice(2);
  const targetEmail = args[0] || process.env.ADMIN_EMAIL || 'admin@cybershield.io';
  const targetPassword = args[1] || process.env.ADMIN_PASSWORD || 'Admin@123456';
  const targetUsername = args[2] || process.env.ADMIN_USERNAME || 'CyberAdmin';

  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';

  console.log('==================================================');
  console.log('  CyberShield — Admin Credential Management Utility');
  console.log('==================================================\n');
  console.log(`[Connecting] Connecting to MongoDB...`);

  try {
    await mongoose.connect(mongoUri);
    console.log('[Connected] Connected to MongoDB.');

    // Hash the new password securely
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(targetPassword, salt);

    // Look for existing admin by role or email
    let admin = await User.findOne({ $or: [{ role: 'admin' }, { email: targetEmail.toLowerCase() }] });

    if (admin) {
      admin.username = targetUsername;
      admin.email = targetEmail.toLowerCase().trim();
      admin.password = hashedPassword;
      admin.role = 'admin';
      admin.isVerified = true;
      await admin.save();

      console.log('\n✅ SUCCESS: Existing Admin account updated!');
      console.log('--------------------------------------------------');
      console.log(` Admin ID:       ${admin._id}`);
      console.log(` Admin Username: ${admin.username}`);
      console.log(` Admin Email:    ${admin.email}`);
      console.log(` New Password:   ${targetPassword}`);
      console.log('--------------------------------------------------\n');
    } else {
      admin = await User.create({
        username: targetUsername,
        email: targetEmail.toLowerCase().trim(),
        password: hashedPassword,
        role: 'admin',
        isVerified: true
      });

      console.log('\n✅ SUCCESS: New Admin account created!');
      console.log('--------------------------------------------------');
      console.log(` Admin ID:       ${admin._id}`);
      console.log(` Admin Username: ${admin.username}`);
      console.log(` Admin Email:    ${admin.email}`);
      console.log(` Password:       ${targetPassword}`);
      console.log('--------------------------------------------------\n');
    }
  } catch (err) {
    console.error('[ERROR] Failed to update Admin account:', err.message);
  } finally {
    await mongoose.disconnect();
    console.log('[Disconnected] MongoDB connection closed.');
  }
}

updateAdmin();
