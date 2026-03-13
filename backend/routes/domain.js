const express = require('express');
const router = express.Router();
const WHOISAnalyzer = require('../services/WHOISAnalyzer');
const SSLInspector = require('../services/SSLInspector');
const DNSAnalyzer = require('../services/DNSAnalyzer');

/**
 * GET /api/domain?domain=example.com
 * Full domain intelligence lookup using modular analyzers
 */
router.get('/', async (req, res, next) => {
  try {
    const { domain } = req.query;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ success: false, error: 'Domain parameter is required' });
    }

    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];

    console.log(`🌐 Deep Domain Lookup: ${cleanDomain}`);

    // Run lookups
    const dnsResults = await DNSAnalyzer.resolve(cleanDomain);
    const [domainInfo, sslStatus] = await Promise.all([
      WHOISAnalyzer.analyze(cleanDomain, dnsResults.ipAddresses),
      SSLInspector.analyze(cleanDomain)
    ]);

    res.json({
      success: true,
      data: {
        domain: cleanDomain,
        registrar: domainInfo.registrar,
        country: domainInfo.country,
        creationDate: domainInfo.creationDate,
        expirationDate: domainInfo.expirationDate,
        nameservers: dnsResults.nameservers,
        hostingProvider: domainInfo.hostingProvider,
        domainAge: domainInfo.age,
        ipAddresses: dnsResults.ipAddresses || [],
        ssl: {
          status: sslStatus.status,
          valid: sslStatus.valid,
          validFrom: sslStatus.validFrom,
          validTo: sslStatus.validTo,
          daysRemaining: sslStatus.daysRemaining
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

