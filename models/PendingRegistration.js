const mongoose = require('mongoose');

const PendingRegistrationSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide a username'],
    trim: true
  },
  email: {
    type: String,
    required: false,
    default: null,
    lowercase: true,
    trim: true
  },
  phoneNumber: {
    type: String,
    required: false,
    default: null,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Please provide a password']
  },
  registrationMethod: {
    type: String,
    enum: ['email', 'phone'],
    required: true
  },
  verificationOTP: {
    type: String,
    required: true
  },
  verificationOTPExpire: {
    type: Date,
    required: true
  },
  otpAttempts: {
    type: Number,
    default: 0
  },
  otpLastSentAt: {
    type: Date,
    default: Date.now
  },
  smsBatchId: {
    type: String,
    default: null
  },
  smsStatus: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 600 // Automatic TTL: MongoDB automatically deletes unverified pending registrations after 10 minutes (600s)
  }
});

// Fast lookup indexes
PendingRegistrationSchema.index({ email: 1 });
PendingRegistrationSchema.index({ phoneNumber: 1 });
PendingRegistrationSchema.index({ username: 1 });

module.exports = mongoose.model('PendingRegistration', PendingRegistrationSchema);
