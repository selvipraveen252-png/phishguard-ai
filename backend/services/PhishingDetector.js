const fs = require('fs');
const path = require('path');

let phishingDomains = new Set();
let malwareDomains = new Set();

try {
  phishingDomains = new Set(JSON.parse(fs.readFileSync(path.join(__dirname, '../data/phishing_domains.json'), 'utf8')));
  malwareDomains = new Set(JSON.parse(fs.readFileSync(path.join(__dirname, '../data/malware_domains.json'), 'utf8')));
} catch (err) {
  console.error('Error loading threat datasets:', err.message);
}

const SUSPICIOUS_KEYWORDS = [

  'login', 'verify', 'secure', 'update', 'account', 'bank',
  'paypal', 'password', 'confirm', 'signin', 'credential',
  'wallet', 'recovery', 'support', 'help-desk', 'ebay',
  'apple-id', 'microsoft', 'netflix', 'amazon', 'alert',
  'auth', 'verification', 'billing', 'customer', 'service'
];

const MAJOR_BRANDS = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'ebay', 'twitter', 'linkedin'];

class PhishingDetector {
  static analyze(url, domain) {
    const urlLower = url.toLowerCase();
    const domainLower = domain.toLowerCase();
    const issues = [];
    let score = 0;

    // 0. Database check
    if (phishingDomains.has(domainLower)) {
        score += 80;
        issues.push("Identified as known Phishing domain");
    }
    if (malwareDomains.has(domainLower)) {
        score += 90;
        issues.push("Identified as known Malware distribution domain");
    }

    // 1. Keyword check

    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
    if (foundKeywords.length > 0) {
      score += 40;
      issues.push(`Suspicious keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
    }

    // 2. Typosquatting check
    const typosquatting = this.detectTyposquatting(domainLower);
    if (typosquatting) {
      score += 20;
      issues.push("Possible Typosquatting Domain");
    }

    // 3. Hyphen count
    const hyphenCount = (domainLower.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 15;
      issues.push("Excessive hyphens in domain");
    }

    return {
      score,
      issues,
      hasTyposquatting: typosquatting
    };
  }

  static detectTyposquatting(domain) {
    const name = domain.split('.')[0];
    for (const brand of MAJOR_BRANDS) {
      if (name === brand) continue;
      
      // Check if it's very similar
      if (name.includes(brand)) return true;

      // Check for common substitutions
      const substituted = name
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/5/g, 's')
        .replace(/3/g, 'e');
        
      if (substituted === brand) return true;

      if (this.levenshteinDistance(name, brand) <= 1) return true;
    }
    return false;
  }

  static levenshteinDistance(s, t) {
    if (!s.length) return t.length;
    if (!t.length) return s.length;
    const arr = [];
    for (let i = 0; i <= t.length; i++) {
        arr[i] = [i];
        for (let j = 1; j <= s.length; j++) {
            arr[i][j] =
                i === 0
                    ? j
                    : Math.min(
                        arr[i - 1][j] + 1,
                        arr[i][j - 1] + 1,
                        arr[i - 1][j - 1] + (s[j - 1] === t[i - 1] ? 0 : 1)
                    );
        }
    }
    return arr[t.length][s.length];
  }
}

module.exports = PhishingDetector;
