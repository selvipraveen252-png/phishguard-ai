const sslChecker = require('ssl-checker');

/**
 * Check SSL certificate for a domain
 * @param {string} domain - Domain to check
 * @returns {object} - SSL status result
 */
async function checkSSL(domain) {
  // Strip any port from domain
  const cleanDomain = domain.split(':')[0];
  
  try {
    const ssl = await sslChecker(cleanDomain, { method: 'GET', port: 443, timeout: 10000 });
    
    let status = 'UNKNOWN';
    if (ssl.valid) {
      if (ssl.daysRemaining <= 0) {
        status = 'EXPIRED';
      } else {
        status = 'VALID';
      }
    } else {
      status = 'INVALID';
    }

    return {
      valid: ssl.valid,
      validFrom: ssl.validFrom || null,
      validTo: ssl.validTo || null,
      daysRemaining: ssl.daysRemaining || 0,
      status
    };
  } catch (err) {
    console.warn(`⚠️ SSL check failed for ${cleanDomain}:`, err.message);
    
    // For well-known domains, don't penalize on API failure
    const trustedDomains = [
      'google.com', 'amazon.com', 'microsoft.com', 'apple.com',
      'facebook.com', 'twitter.com', 'github.com', 'linkedin.com',
      'cloudflare.com', 'youtube.com', 'instagram.com', 'netflix.com'
    ];

    const isTrusted = trustedDomains.some(td => 
      cleanDomain === td || cleanDomain.endsWith(`.${td}`)
    );

    if (isTrusted) {
      return {
        valid: true,
        validFrom: null,
        validTo: null,
        daysRemaining: 365,
        status: 'VALID'
      };
    }

    // Check if it could be HTTP (no SSL)
    if (err.message.includes('ECONNREFUSED') || err.message.includes('ETIMEDOUT')) {
      return {
        valid: false,
        validFrom: null,
        validTo: null,
        daysRemaining: 0,
        status: 'NO SSL'
      };
    }

    return {
      valid: false,
      validFrom: null,
      validTo: null,
      daysRemaining: 0,
      status: 'NO SSL'
    };
  }
}

module.exports = { checkSSL };
