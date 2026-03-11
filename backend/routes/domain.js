const express = require('express');
const router = express.Router();
const { getDomainIntel } = require('../services/domainIntel');
const { checkSSL } = require('../services/sslChecker');

/**
 * GET /api/domain?domain=example.com
 * Full domain intelligence lookup
 */
router.get('/', async (req, res, next) => {
  try {
    const { domain } = req.query;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ success: false, error: 'Domain parameter is required' });
    }

    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];

    console.log(`🌐 Domain lookup: ${cleanDomain}`);

    const [domainInfo, sslStatus] = await Promise.all([
      getDomainIntel(cleanDomain).catch(e => ({ 
        age: null, 
        registrar: 'Unknown', 
        country: 'Unknown',
        error: e.message 
      })),
      checkSSL(cleanDomain).catch(e => ({ 
        valid: false, 
        status: 'NO SSL', 
        daysRemaining: 0 
      }))
    ]);

    res.json({
      success: true,
      data: {
        domain: cleanDomain,
        registrar: domainInfo.registrar,
        country: domainInfo.country,
        creationDate: domainInfo.creationDate,
        expirationDate: domainInfo.expirationDate,
        nameservers: domainInfo.nameservers,
        hostingProvider: domainInfo.hostingProvider,
        domainAge: domainInfo.age,
        ipAddresses: domainInfo.ipAddresses || [],
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
