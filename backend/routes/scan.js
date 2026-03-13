const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const ThreatEngine = require('../services/ThreatEngine');
const { extractDomain, normalizeUrl } = require('../services/phishingAnalyzer');

/**
 * POST /api/scan
 * Full phishing analysis pipeline using modular ThreatEngine
 */
router.post('/', async (req, res, next) => {
  try {
    let { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ success: false, error: 'URL is required' });
    }

    url = url.trim();

    // Validate URL format
    const normalizedUrl = normalizeUrl(url);
    try {
      new URL(normalizedUrl);
    } catch (e) {
      return res.status(400).json({ success: false, error: 'Invalid URL format' });
    }

    const domain = extractDomain(normalizedUrl);

    console.log(`🔍 Deep Scan Initiated: ${normalizedUrl} (Domain: ${domain})`);

    // Use the new ThreatEngine for analysis
    const analysis = await ThreatEngine.analyze(normalizedUrl, domain);

    // Build full result (Ensuring compatibility with existing frontend JSON structure)
    const result = {
      url: normalizedUrl,
      domain,
      threatScore: analysis.threatScore,
      phishingProbability: analysis.phishingProbability,
      riskLevel: analysis.riskLevel,
      issues: analysis.issues,
      piracyStatus: analysis.piracyStatus,
      sslStatus: analysis.sslStatus,
      domainInfo: analysis.domainInfo,
      virusTotal: analysis.virusTotal,
      googleSafeBrowsing: analysis.googleSafeBrowsing
    };

    // Save to MongoDB
    const scan = new Scan(result);
    await scan.save();

    console.log(`✅ Deep Scan Complete: ${domain} | Score: ${analysis.threatScore} | Risk: ${analysis.riskLevel}`);

    res.json({ success: true, data: { ...result, _id: scan._id, createdAt: scan.createdAt } });
  } catch (err) {
    console.error(`❌ Scan failed for ${req.body.url}:`, err.message);
    next(err);
  }
});

/**
 * GET /api/scan/history
 * Get scan history with pagination
 */
router.get('/history', async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Scan.countDocuments()
    ]);

    res.json({
      success: true,
      data: scans,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

