require('dotenv').config();
const axios = require('axios');

const apiKey = process.env.GEMINI_API_KEY;

async function testKey() {
  if (!apiKey) {
    console.log('Error: GEMINI_API_KEY environment variable not set.');
    return;
  }
  console.log('Testing GEMINI_API_KEY...');
  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${apiKey}`;
    const res = await axios.post(endpoint, {
      contents: [{ parts: [{ text: 'Respond with "Gemini API Active"' }] }]
    });
    console.log('Response:', res.data.candidates[0].content.parts[0].text);
  } catch (err) {
    console.error('API Test Error:', err.response?.data?.error?.message || err.message);
  }
}

testKey();
