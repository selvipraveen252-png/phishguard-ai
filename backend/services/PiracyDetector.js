const fs = require('fs');
const path = require('path');

let piracyDomains = new Set();

try {
  const data = fs.readFileSync(path.join(__dirname, '../data/piracy_domains.json'), 'utf8');
  piracyDomains = new Set(JSON.parse(data));
} catch (err) {
  console.error('Error loading piracy domains:', err.message);
}

/**
 * Detect piracy-related content
 */
class PiracyDetector {
  static analyze(url, domain) {
    const lowerUrl = url.toLowerCase();
    const lowerDomain = domain.toLowerCase();

    // Check database
    if (piracyDomains.has(lowerDomain) || piracyDomains.has(lowerDomain.replace(/^www\./, ''))) {
      return {
        detected: true,
        type: "Piracy Content Distribution",
        score: 40,
        riskLevel: "HIGH"
      };
    }

    // Pattern matching (fallback)
    const piracyKeywords = [
      "fitgirl", "repack", "torrent", "crack", "warez",
      "camrip", "dvdrip", "hdrip", "free-movie", "movie-download",
      "anime-download", "watch-free", "free-anime", "stream-anime"
    ];

    const foundKeywords = piracyKeywords.some(kw => lowerUrl.includes(kw));
    const riskyTLDs = [".to", ".sx", ".cx", ".site", ".download", ".stream", ".games", ".ru"];
    const isRiskyTLD = riskyTLDs.some(tld => lowerDomain.endsWith(tld));

    if (foundKeywords && isRiskyTLD) {
      return {
        detected: true,
        type: "Piracy Content Distribution",
        score: 40,
        riskLevel: "HIGH"
      };
    }

    if (foundKeywords || isRiskyTLD) {
        return {
            detected: true,
            type: "Possible Piracy Signals",
            score: 20,
            riskLevel: "SUSPICIOUS"
        }
    }

    return {
      detected: false,
      type: null,
      score: 0,
      riskLevel: "SAFE"
    };
  }
}

module.exports = PiracyDetector;
