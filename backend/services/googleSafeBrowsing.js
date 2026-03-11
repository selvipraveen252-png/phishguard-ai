const axios = require('axios');

/**
 * Query Google Safe Browsing API v4
 * @param {string} url - URL to check
 * @returns {object} - Safe Browsing result
 */
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  
  if (!apiKey) {
    console.warn('⚠️ Google Safe Browsing API key not configured');
    return { isSafe: true, threats: [], error: 'API key not configured' };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    
    const requestBody = {
      client: {
        clientId: 'phishguard-ai',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION'
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };

    const response = await axios.post(endpoint, requestBody, {
      timeout: 8000,
      headers: { 'Content-Type': 'application/json' }
    });

    const matches = response.data.matches || [];
    
    if (matches.length > 0) {
      const threats = matches.map(m => m.threatType);
      return {
        isSafe: false,
        threats,
        raw: matches
      };
    }

    return { isSafe: true, threats: [] };
  } catch (err) {
    console.error('❌ Google Safe Browsing error:', err.response?.data || err.message);
    return { isSafe: true, threats: [], error: err.message };
  }
}

module.exports = { checkGoogleSafeBrowsing };
