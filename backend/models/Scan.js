const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    trim: true
  },
  domain: {
    type: String,
    required: true,
    trim: true
  },
  threatScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  phishingProbability: {
    type: String,
    default: 'Low'
  },
  riskLevel: {
    type: String,
    enum: ['SAFE', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK', 'MALICIOUS', 'TRUSTED PLATFORM', 'INVALID DOMAIN'],
    default: 'SAFE'
  },
  issues: {
    type: [String],
    default: []
  },
  piracyStatus: {
    type: String,
    default: 'No Piracy Signals'
  },
  sslStatus: {
    valid: { type: Boolean, default: false },
    validFrom: { type: String, default: null },
    validTo: { type: String, default: null },
    daysRemaining: { type: Number, default: 0 },
    status: { type: String, default: 'UNKNOWN' }
  },
  domainInfo: {
    age: { type: Number, default: null },
    registrar: { type: String, default: null },
    country: { type: String, default: null },
    creationDate: { type: String, default: null },
    expirationDate: { type: String, default: null },
    hostingProvider: { type: String, default: 'Unknown' },
    nameservers: { type: [String], default: [] }
  },

  virusTotal: {
    malicious: { type: Number, default: 0 },
    suspicious: { type: Number, default: 0 },
    harmless: { type: Number, default: 0 },
    undetected: { type: Number, default: 0 },
    totalEngines: { type: Number, default: 0 },
    permalink: { type: String, default: null },
    scanDate: { type: String, default: null }
  },
  googleSafeBrowsing: {
    isSafe: { type: Boolean, default: true },
    threats: { type: [String], default: [] }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

scanSchema.index({ createdAt: -1 });
scanSchema.index({ domain: 1 });
scanSchema.index({ riskLevel: 1 });

module.exports = mongoose.model('Scan', scanSchema);
