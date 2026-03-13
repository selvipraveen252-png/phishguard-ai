/**
 * Phishing Analyzer - Heuristic scoring engine
 * Analyzes a URL and its intelligence data to compute a threat score
 */

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account', 'bank',
  'paypal', 'password', 'confirm', 'signin', 'credential',
  'wallet', 'recovery', 'support', 'help-desk', 'ebay',
  'apple-id', 'microsoft', 'netflix', 'amazon', 'alert',
  'auth', 'verification', 'billing', 'customer', 'service'
];

const TRUSTED_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "instagram.com",
  "twitter.com", "linkedin.com", "wikipedia.org", "github.com",
  "microsoft.com", "apple.com", "amazon.com", "netflix.com",
  "openai.com", "stackoverflow.com", "reddit.com", "cloudflare.com",
  "mozilla.org", "bing.com", "yahoo.com", "zoom.us", "figma.com", "notion.so"
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
  const domainLower = domain.toLowerCase();
  const urlLower = url.toLowerCase();

  // LAYER 1 — TRUSTED DOMAIN WHITELIST
  const isWhitelisted = TRUSTED_DOMAINS.some(td => 
    domainLower === td || domainLower.endsWith(`.${td}`)
  );

  if (isWhitelisted) {
    return {
      threatScore: 0,
      phishingProbability: 'Very Low',
      riskLevel: 'TRUSTED PLATFORM',
      issues: ['Validated: Trusted Enterprise Platform']
    };
  }

  // LAYER 6 — GOOGLE SAFE BROWSING (CRITICAL)
  if (googleSafeBrowsing && !googleSafeBrowsing.isSafe) {
    score += 85; 
    issues.push('Blacklist: High Risk - Flagged by Google Safe Browsing');
  }

  // LAYER 5 — VIRUSTOTAL INTELLIGENCE
  const vtMalicious = virusTotal?.malicious || 0;
  if (vtMalicious >= 2) {
    score += Math.min(60, vtMalicious * 15);
    issues.push(`Intel: ${vtMalicious} Security Engines flagged as Malicious`);
  } else if (vtMalicious === 1) {
    issues.push('Note: Single security flag detected (Potential False Positive)');
    score += 10;
  }

  // LAYER 2 — PHISHING DOMAIN PATTERN DETECTION
  // Typosquatting / Lookalikes (Simple check for common impersonations)
  const impersonationTargets = ['google', 'paypal', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix'];
  const hasLookalike = impersonationTargets.some(target => 
    domainLower.includes(target) && domainLower !== target && !domainLower.endsWith(`.${target}.com`)
  );
  if (hasLookalike) {
    score += 35;
    issues.push('Pattern: Suspicious Domain Typosquatting/Impersonation detected');
  }

  // Extra hyphens
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    score += 15;
    issues.push('Pattern: Excessive hyphens in domain structure');
  }

  // Suspicious keywords
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
  if (foundKeywords.length > 0) {
    score += 20;
    issues.push(`Pattern: Suspicious keywords detected (${foundKeywords.slice(0, 2).join(', ')})`);
  }

  // LAYER 4 — DOMAIN REPUTATION ANALYSIS
  // Domain Age
  if (domainInfo && domainInfo.age !== null) {
    if (domainInfo.age < 30) {
      score += 40;
      issues.push('Reputation: Critical - Domain is less than 30 days old');
    } else if (domainInfo.age < 90) {
      score += 20;
      issues.push('Reputation: Suspicious - Recently registered domain');
    }
  }

  // SSL Validity
  const hasValidSSL = sslStatus && sslStatus.valid && sslStatus.status === 'VALID';
  if (!hasValidSSL) {
    score += 25;
    issues.push(`Reputation: Security risk - Invalid or missing SSL (${sslStatus?.status || 'NO SSL'})`);
  }

  // Hosting / Registrar Risk
  if (domainInfo?.registrar === 'Unknown') {
    score += 10;
    issues.push('Reputation: Unknown or obfuscated registrar');
  }

  // Final score normalization
  score = Math.max(0, Math.min(100, score));

  // FINAL THREAT SCORING MODEL
  // 0-20 → SAFE, 21-40 → LOW RISK, 41-70 → SUSPICIOUS, 71-100 → HIGH RISK
  let riskLevel;
  let phishingProbability;

  if (score <= 20) {
    riskLevel = 'SAFE';
    phishingProbability = 'Low';
  } else if (score <= 40) {
    riskLevel = 'LOW RISK';
    phishingProbability = 'Moderate';
  } else if (score <= 70) {
    riskLevel = 'SUSPICIOUS';
    phishingProbability = 'High';
  } else {
    riskLevel = 'HIGH RISK';
    phishingProbability = 'Critical';
  }

  return {
    threatScore: score,
    phishingProbability,
    riskLevel,
    issues: issues.length > 0 ? issues : ['Validated: No significant threat indicators found']
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
