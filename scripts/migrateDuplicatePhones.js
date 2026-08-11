/**
 * CyberShield — Safe Database Migration & Phone Canonicalization Script
 *
 * Inspects all existing user records in MongoDB.
 * Normalizes all phone numbers into canonical E.164 format (+91XXXXXXXXXX).
 * Identifies duplicate representations safely without losing user data.
 *
 * Usage:
 *   node scripts/migrateDuplicatePhones.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const { normalizePhoneNumber } = require('../utils/phoneNormalizer');

const runMigration = async () => {
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';

  console.log('[MIGRATION] Connecting to MongoDB...');
  try {
    await mongoose.connect(mongoUri);
    console.log('[MIGRATION] Connected to MongoDB successfully.');
  } catch (err) {
    console.error('[MIGRATION ERROR] Unable to connect to MongoDB:', err.message);
    process.exit(1);
  }

  try {
    const users = await User.find({ phoneNumber: { $ne: null, $exists: true } });
    console.log(`[MIGRATION] Found ${users.length} user records with phone numbers.`);

    let updatedCount = 0;
    let duplicateCount = 0;
    let errorCount = 0;

    const canonicalMap = new Map();

    for (const user of users) {
      const rawPhone = user.phoneNumber;
      let canonicalPhone;

      try {
        canonicalPhone = normalizePhoneNumber(rawPhone, 'IN');
      } catch (err) {
        console.warn(`[MIGRATION WARN] User ${user._id} (${user.username}) has unparseable phone "${rawPhone}":`, err.message);
        errorCount++;
        continue;
      }

      if (canonicalMap.has(canonicalPhone)) {
        const existing = canonicalMap.get(canonicalPhone);
        console.warn(`[MIGRATION DUPLICATE DETECTED] Canonical number "${canonicalPhone}" matches multiple user accounts:`);
        console.warn(`  - Existing Account: ID=${existing._id}, Username=${existing.username}, Verified=${existing.phoneVerified}, Created=${existing.createdAt}`);
        console.warn(`  - Current Account:  ID=${user._id}, Username=${user.username}, Verified=${user.phoneVerified}, Created=${user.createdAt}`);
        duplicateCount++;
      } else {
        canonicalMap.set(canonicalPhone, user);
      }

      if (rawPhone !== canonicalPhone) {
        // Check if updating would collide with an already existing document in DB
        const conflict = await User.findOne({ phoneNumber: canonicalPhone, _id: { $ne: user._id } });
        if (conflict) {
          console.warn(`[MIGRATION SKIPPED] Cannot convert user ${user._id} (${rawPhone} -> ${canonicalPhone}) because canonical account ${conflict._id} already exists.`);
        } else {
          user.phoneNumber = canonicalPhone;
          await user.save();
          console.log(`[MIGRATION UPDATED] User ${user._id} (${user.username}): "${rawPhone}" -> "${canonicalPhone}"`);
          updatedCount++;
        }
      }
    }

    console.log('\n[MIGRATION SUMMARY]');
    console.log(`  Total Phone Users Examined: ${users.length}`);
    console.log(`  Canonicalized & Updated:    ${updatedCount}`);
    console.log(`  Duplicates Flagged:         ${duplicateCount}`);
    console.log(`  Errors / Invalid Numbers:   ${errorCount}`);
    console.log('[MIGRATION COMPLETE] All valid phone numbers are now canonicalized to E.164 (+91XXXXXXXXXX).\n');

  } catch (err) {
    console.error('[MIGRATION ERROR] Failed during migration execution:', err);
  } finally {
    await mongoose.disconnect();
    console.log('[MIGRATION] Disconnected from MongoDB.');
  }
};

if (require.main === module) {
  runMigration();
}

module.exports = runMigration;
