const axios = require('axios');

/**
 * Submit URL to VirusTotal for analysis and retrieve results
 * @param {string} url - URL to scan
 * @returns {object} - VirusTotal analysis result
 */
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  
  if (!apiKey) {
    console.warn('⚠️ VirusTotal API key not configured');
    return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0, permalink: null, scanDate: null, error: 'API key not configured' };
  }

  try {
    // Step 1: Submit URL for scanning
    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
      }
    );

    const analysisId = submitResponse.data?.data?.id;
    if (!analysisId) {
      throw new Error('No analysis ID returned from VirusTotal');
    }

    // Step 2: Poll for results (wait up to 20 seconds)
    let analysisResult = null;
    let attempts = 0;
    const maxAttempts = 4;

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      try {
        const resultResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          {
            headers: { 'x-apikey': apiKey },
            timeout: 10000
          }
        );

        const status = resultResponse.data?.data?.attributes?.status;
        
        if (status === 'completed') {
          analysisResult = resultResponse.data.data.attributes;
          break;
        }
      } catch (pollErr) {
        console.warn(`VT poll attempt ${attempts + 1} failed:`, pollErr.message);
      }
      
      attempts++;
    }

    if (!analysisResult) {
      // Try to get URL object directly using URL ID
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      try {
        const urlResponse = await axios.get(
          `https://www.virustotal.com/api/v3/urls/${urlId}`,
          {
            headers: { 'x-apikey': apiKey },
            timeout: 10000
          }
        );
        analysisResult = urlResponse.data?.data?.attributes?.last_analysis_stats 
          ? { stats: urlResponse.data.data.attributes.last_analysis_stats }
          : null;
          
        if (analysisResult) {
          const stats = analysisResult.stats;
          return {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
            permalink: `https://www.virustotal.com/gui/url/${urlId}`,
            scanDate: urlResponse.data?.data?.attributes?.last_analysis_date 
              ? new Date(urlResponse.data.data.attributes.last_analysis_date * 1000).toISOString()
              : new Date().toISOString()
          };
        }
      } catch (e) {
        console.warn('VT URL lookup fallback failed:', e.message);
      }

      return {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        totalEngines: 0,
        permalink: null,
        scanDate: null,
        error: 'Analysis timed out'
      };
    }

    const stats = analysisResult.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const totalEngines = malicious + suspicious + harmless + undetected + (stats.timeout || 0);

    return {
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines,
      permalink: `https://www.virustotal.com/gui/url/${analysisId}`,
      scanDate: new Date().toISOString()
    };
  } catch (err) {
    console.error('❌ VirusTotal error:', err.response?.data?.error || err.message);
    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      permalink: null,
      scanDate: null,
      error: err.message
    };
  }
}

module.exports = { checkVirusTotal };
