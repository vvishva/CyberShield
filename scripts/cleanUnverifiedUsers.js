/**
 * CyberShield — Safe Database Inspection & Abandoned Account Cleanup Script
 *
 * Inspects all user records in MongoDB User collection.
 * Identifies accounts created during broken registration flows that were NEVER verified:
 *   - emailVerified / isVerified == false AND phoneVerified == false
 *
 * Defaults to DRY-RUN mode (safe report). Pass --execute flag to perform deletion.
 *
 * Usage:
 *   node scripts/cleanUnverifiedUsers.js            (Dry Run - Safe Inspection)
 *   node scripts/cleanUnverifiedUsers.js --execute  (Execute Cleanup)
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

const runCleanup = async () => {
  const isExecute = process.argv.includes('--execute');
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';

  console.log(`[CLEANUP] Connecting to MongoDB (${isExecute ? 'EXECUTE MODE' : 'DRY RUN MODE'})...`);
  try {
    await mongoose.connect(mongoUri);
    console.log('[CLEANUP] Connected to MongoDB.');
  } catch (err) {
    console.error('[CLEANUP ERROR] Failed to connect to MongoDB:', err.message);
    process.exit(1);
  }

  try {
    const allUsers = await User.find({});
    console.log(`[CLEANUP] Total User accounts in collection: ${allUsers.length}`);

    const verifiedUsers = [];
    const abandonedUsers = [];

    for (const u of allUsers) {
      // Do NOT classify admins as abandoned
      if (u.role === 'admin') {
        verifiedUsers.push(u);
        continue;
      }

      // Check verification status
      const hasVerifiedEmail = u.isVerified === true && u.email;
      const hasVerifiedPhone = u.phoneVerified === true && u.phoneNumber;

      if (hasVerifiedEmail || hasVerifiedPhone) {
        verifiedUsers.push(u);
      } else {
        abandonedUsers.push(u);
      }
    }

    console.log('\n==================================================');
    console.log('                 CLEANUP REPORT                   ');
    console.log('==================================================');
    console.log(`Legitimate Verified / Admin Accounts: ${verifiedUsers.length}`);
    console.log(`Abandoned Unverified Test Accounts:   ${abandonedUsers.length}\n`);

    if (abandonedUsers.length === 0) {
      console.log('[CLEANUP] No abandoned unverified accounts found.');
    } else {
      console.log('ABANDONED ACCOUNTS CLASSIFIED FOR REMOVAL:');
      console.log('--------------------------------------------------');
      abandonedUsers.forEach((u, i) => {
        const maskedEmail = u.email ? u.email.replace(/(.{2})(.*)(?=@)/, '$1***') : 'N/A';
        const maskedPhone = u.phoneNumber ? u.phoneNumber.replace(/\d(?=\d{4})/g, '*') : 'N/A';
        const created = u.createdAt ? new Date(u.createdAt).toISOString() : 'Unknown';
        console.log(`${i+1}. ID: ${u._id} | User: ${u.username} | Email: ${maskedEmail} | Phone: ${maskedPhone} | Created: ${created} | Reason: Unverified Registration`);
      });
      console.log('--------------------------------------------------\n');

      if (isExecute) {
        console.log('[CLEANUP] Deleting identified abandoned accounts...');
        const abandonedIds = abandonedUsers.map(u => u._id);
        const result = await User.deleteMany({ _id: { $in: abandonedIds } });
        console.log(`[CLEANUP SUCCESS] Deleted ${result.deletedCount} unverified abandoned accounts.`);
      } else {
        console.log('[DRY RUN COMPLETE] No records were deleted.');
        console.log('To perform actual deletion, run: node scripts/cleanUnverifiedUsers.js --execute\n');
      }
    }

  } catch (err) {
    console.error('[CLEANUP ERROR] Script failed:', err);
  } finally {
    await mongoose.disconnect();
    console.log('[CLEANUP] Disconnected from MongoDB.');
  }
};

if (require.main === module) {
  runCleanup();
}

module.exports = runCleanup;
