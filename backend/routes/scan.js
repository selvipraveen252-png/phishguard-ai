const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const { checkGoogleSafeBrowsing } = require('../services/googleSafeBrowsing');
const { checkVirusTotal } = require('../services/virusTotal');
const { checkSSL } = require('../services/sslChecker');
const { getDomainIntel } = require('../services/domainIntel');
const { analyzePhishing, extractDomain, normalizeUrl } = require('../services/phishingAnalyzer');

/**
 * POST /api/scan
 * Full phishing analysis pipeline
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

    console.log(`🔍 Scanning: ${normalizedUrl} (Domain: ${domain})`);

    // Run all analysis in parallel for speed
    const [googleSafeBrowsing, virusTotal, sslStatus, domainInfo] = await Promise.all([
      checkGoogleSafeBrowsing(normalizedUrl).catch(e => ({ isSafe: true, threats: [], error: e.message })),
      checkVirusTotal(normalizedUrl).catch(e => ({ malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0, error: e.message })),
      checkSSL(domain).catch(e => ({ valid: false, status: 'NO SSL', daysRemaining: 0, error: e.message })),
      getDomainIntel(domain).catch(e => ({ age: null, registrar: 'Unknown', country: 'Unknown', error: e.message }))
    ]);

    // Compute phishing score
    const analysis = analyzePhishing({
      url: normalizedUrl,
      domain,
      googleSafeBrowsing,
      virusTotal,
      sslStatus,
      domainInfo
    });

    // Build full result
    const result = {
      url: normalizedUrl,
      domain,
      threatScore: analysis.threatScore,
      phishingProbability: analysis.phishingProbability,
      riskLevel: analysis.riskLevel,
      issues: analysis.issues,
      sslStatus: {
        valid: sslStatus.valid,
        validFrom: sslStatus.validFrom,
        validTo: sslStatus.validTo,
        daysRemaining: sslStatus.daysRemaining,
        status: sslStatus.status
      },
      domainInfo: {
        age: domainInfo.age,
        registrar: domainInfo.registrar,
        country: domainInfo.country,
        creationDate: domainInfo.creationDate,
        expirationDate: domainInfo.expirationDate,
        nameservers: domainInfo.nameservers
      },
      virusTotal: {
        malicious: virusTotal.malicious,
        suspicious: virusTotal.suspicious,
        harmless: virusTotal.harmless,
        undetected: virusTotal.undetected,
        totalEngines: virusTotal.totalEngines,
        permalink: virusTotal.permalink,
        scanDate: virusTotal.scanDate
      },
      googleSafeBrowsing: {
        isSafe: googleSafeBrowsing.isSafe,
        threats: googleSafeBrowsing.threats
      }
    };

    // Save to MongoDB
    const scan = new Scan(result);
    await scan.save();

    console.log(`✅ Scan saved: ${domain} | Score: ${analysis.threatScore} | Risk: ${analysis.riskLevel}`);

    res.json({ success: true, data: { ...result, _id: scan._id, createdAt: scan.createdAt } });
  } catch (err) {
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
