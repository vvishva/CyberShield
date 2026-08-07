const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const connStr = process.env.MONGO_URI || 'mongodb://localhost:27017/cybershield';
    const conn = await mongoose.connect(connStr);
    console.log(`[CyberShield DB] MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.warn(`[CyberShield DB Warning] MongoDB Connection Failed: ${error.message}. Running with memory fallback handler.`);
  }
};

module.exports = connectDB;
