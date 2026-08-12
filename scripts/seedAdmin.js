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

async function seedAdmin() {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';
    await mongoose.connect(mongoUri);
    console.log('[Seed] Connected to MongoDB');

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@cybershield15043001.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin@15043001';
    const adminUsername = process.env.ADMIN_USERNAME || 'CyberShieldAdmin';

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);

    let admin = await User.findOne({ $or: [{ role: 'admin' }, { email: adminEmail.toLowerCase() }] });

    if (admin) {
      admin.username = adminUsername;
      admin.email = adminEmail.toLowerCase().trim();
      admin.password = hashedPassword;
      admin.role = 'admin';
      admin.isVerified = true;
      await admin.save();
      console.log('[Seed] Existing Admin updated successfully:', admin.email);
    } else {
      admin = await User.create({
        username: adminUsername,
        email: adminEmail.toLowerCase().trim(),
        password: hashedPassword,
        role: 'admin',
        isVerified: true
      });
      console.log('[Seed] Admin user created successfully:', admin.email);
    }

    console.log('[Seed] Role:', admin.role);
    console.log('[Seed] Username:', admin.username);
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