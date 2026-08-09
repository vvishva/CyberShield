require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6, select: false },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  avatar: { type: String, default: 'avatar-cyber-1.png' },
  twoFactorEnabled: { type: Boolean, default: false },
  emailNotifications: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', UserSchema);

async function seedAdmin() {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';
    await mongoose.connect(mongoUri);
    console.log('[Seed] Connected to MongoDB');

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@cybershield.io';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';
    const adminUsername = process.env.ADMIN_USERNAME || 'CyberAdmin';

    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log('[Seed] Admin user already exists:', adminEmail);
      await mongoose.disconnect();
      return;
    }

    const admin = await User.create({
      username: adminUsername,
      email: adminEmail,
      password: adminPassword,
      role: 'admin'
    });

    console.log('[Seed] Admin user created successfully:', admin.email);
    console.log('[Seed] Role:', admin.role);
  } catch (error) {
    console.error('[Seed] Error:', error.message);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

seedAdmin();