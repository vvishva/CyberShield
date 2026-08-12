/**
 * CyberShield — Google Authentication Backend Diagnostic Test
 */

require('dotenv').config();
const { verifyGoogleToken } = require('../utils/googleAuth');

async function testGoogleVerification() {
  console.log('==================================================');
  console.log('  CyberShield — Google Auth Verification Diagnostic');
  console.log('==================================================\n');

  console.log('1. Checking GOOGLE_CLIENT_ID env var...');
  console.log('   GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID || '829471928471-cybershield.apps.googleusercontent.com (Default)');
  
  console.log('\n2. Testing rejection of empty/invalid tokens...');
  try {
    await verifyGoogleToken('invalid_test_token_123');
    console.error('❌ FAIL: Invalid token was erroneously accepted.');
  } catch (err) {
    console.log('✅ PASS: Invalid token correctly rejected with message:', err.message);
  }

  console.log('\n3. Testing empty payload rejection...');
  try {
    await verifyGoogleToken('');
    console.error('❌ FAIL: Empty token was erroneously accepted.');
  } catch (err) {
    console.log('✅ PASS: Empty token correctly rejected with message:', err.message);
  }

  console.log('\n==================================================');
  console.log('  Google Auth Backend Diagnostic Complete!');
  console.log('==================================================\n');
}

testGoogleVerification();
