/**
 * Phishing Analyzer - Heuristic scoring engine
 * Analyzes a URL and its intelligence data to compute a threat score
 */

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account', 'bank',
  'paypal', 'password', 'confirm', 'signin', 'credential',
  'wallet', 'recovery', 'support', 'help-desk', 'ebay',
  'apple-id', 'microsoft', 'netflix', 'amazon', 'alert'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.gq', '.ml', '.cf', '.tk', '.ga',
  '.pw', '.cc', '.su', '.icu', '.vip', '.online', '.site',
  '.click', '.link', '.win', '.download', '.loan', '.work'
];

/**
 * Analyze URL and all intelligence data to produce threat score
 */
function analyzePhishing({
  url,
  domain,
  googleSafeBrowsing,
  virusTotal,
  sslStatus,
  domainInfo
}) {
  let score = 0;
  const issues = [];

  // VirusTotal malicious detection (+40)
  if (virusTotal && virusTotal.malicious > 0) {
    score += 40;
    issues.push(`VirusTotal: ${virusTotal.malicious} engines flagged as malicious`);
  }

  // VirusTotal suspicious (+15)
  if (virusTotal && virusTotal.suspicious > 0 && virusTotal.malicious === 0) {
    score += 15;
    issues.push(`VirusTotal: ${virusTotal.suspicious} engines flagged as suspicious`);
  }

  // Google Safe Browsing flagged (+40)
  if (googleSafeBrowsing && !googleSafeBrowsing.isSafe) {
    score += 40;
    const threats = googleSafeBrowsing.threats.join(', ');
    issues.push(`Google Safe Browsing: Threat detected - ${threats}`);
  }

  // Domain age < 30 days (+15)
  if (domainInfo && domainInfo.age !== null && domainInfo.age < 30) {
    score += 15;
    issues.push(`Newly registered domain (${domainInfo.age} days old)`);
  } else if (domainInfo && domainInfo.age !== null && domainInfo.age < 90) {
    score += 5;
    issues.push(`Recently registered domain (${domainInfo.age} days old)`);
  }

  // Invalid/No SSL (+10)
  if (sslStatus && (sslStatus.status === 'NO SSL' || sslStatus.status === 'INVALID')) {
    score += 10;
    issues.push(`SSL Certificate: ${sslStatus.status}`);
  } else if (sslStatus && sslStatus.status === 'EXPIRED') {
    score += 8;
    issues.push('SSL Certificate is expired');
  }

  // Suspicious keywords in URL (+10)
  const urlLower = url.toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
  if (foundKeywords.length > 0) {
    score += Math.min(10, foundKeywords.length * 3);
    issues.push(`Suspicious keywords detected: ${foundKeywords.slice(0, 3).join(', ')}`);
  }

  // Suspicious TLD (+10)
  const domainLower = domain.toLowerCase();
  const foundTLD = SUSPICIOUS_TLDS.find(tld => domainLower.endsWith(tld));
  if (foundTLD) {
    score += 10;
    issues.push(`Suspicious TLD detected: ${foundTLD}`);
  }

  // IP address as domain (+15)
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(domain)) {
    score += 15;
    issues.push('URL uses IP address instead of domain name');
  }

  // Multiple subdomains (+8)
  const subdomain = domain.replace(/^www\./, '');
  const parts = subdomain.split('.');
  if (parts.length > 3) {
    score += 8;
    issues.push(`Excessive subdomains detected (${parts.length - 2} levels)`);
  }

  // Very long URL (+5)
  if (url.length > 100) {
    score += 5;
    issues.push(`Unusually long URL (${url.length} characters)`);
  }

  // URL encoding / obfuscation (+8)
  const encodingPattern = /%[0-9a-fA-F]{2}/g;
  const encodedParts = url.match(encodingPattern) || [];
  if (encodedParts.length > 3) {
    score += 8;
    issues.push(`Heavy URL encoding detected (${encodedParts.length} encoded characters)`);
  }

  // Hyphen-heavy domain (+5)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 5;
    issues.push(`Multiple hyphens in domain name (${hyphenCount} hyphens)`);
  }

  // Cap at 100
  score = Math.min(100, score);

  // Determine risk level
  let riskLevel;
  let phishingProbability;

  if (score <= 25) {
    riskLevel = 'SAFE';
    phishingProbability = 'Low';
  } else if (score <= 60) {
    riskLevel = 'SUSPICIOUS';
    phishingProbability = 'Medium';
  } else {
    riskLevel = 'HIGH RISK';
    phishingProbability = 'High';
  }

  return {
    threatScore: score,
    phishingProbability,
    riskLevel,
    issues
  };
}

/**
 * Normalize and extract domain from URL
 */
function extractDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (e) {
    // Try adding protocol
    try {
      const parsed = new URL(`https://${url}`);
      return parsed.hostname;
    } catch (e2) {
      return url;
    }
  }
}

/**
 * Normalize URL - ensure it has a protocol
 */
function normalizeUrl(url) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return `https://${url}`;
  }
  return url;
}

module.exports = { analyzePhishing, extractDomain, normalizeUrl };
