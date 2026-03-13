const ReputationScanner = require('./ReputationScanner');
const DNSAnalyzer = require('./DNSAnalyzer');
const SSLInspector = require('./SSLInspector');
const WHOISAnalyzer = require('./WHOISAnalyzer');
const PiracyDetector = require('./PiracyDetector');
const PhishingDetector = require('./PhishingDetector');

const cache = new Map();
const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes

class ThreatEngine {
  static async analyze(url, domain) {
    const cacheKey = `${url}:${domain}`;
    if (cache.has(cacheKey)) {
        const cached = cache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_DURATION) {
            console.log(`[Cache] Returning cached result for ${domain}`);
            return cached.data;
        }
    }

    console.log(`[ThreatEngine] Starting deep analysis for ${domain}`);

    // STEP 1: DNS Resolution Check (Requirement 1)
    const dnsExistence = await DNSAnalyzer.checkExistence(domain);
    if (!dnsExistence.exists) {
      const whoisReg = await WHOISAnalyzer.checkRegistration(domain);
      
      const result = {
        threatScore: whoisReg.isRegistered ? 90 : 95,
        riskLevel: "SUSPICIOUS", // Mapping to existing frontend categories for color coding
        phishingProbability: "Critical",
        issues: [
          "⚠ Domain Not Found",
          "This domain does not exist in DNS records.",
          "Possible typo, parked domain, or fake phishing link.",
          `Detection: ${whoisReg.isRegistered ? "INVALID DOMAIN (DNS FAILURE)" : "UNREGISTERED DOMAIN"}`,
          `DNS Error Code: ${dnsExistence.error}`,
          whoisReg.isRegistered ? "Domain is registered but inactive/dead" : "Domain is NOT registered (No WHOIS records)"
        ],
        piracyStatus: "No Piracy Signals",
        sslStatus: { valid: false, status: "[ INSECURE ]", actualStatus: "NO SSL", daysRemaining: 0 },
        domainInfo: {
          age: null, registrar: whoisReg.isRegistered ? "Hidden/Protected" : "AVAILABLE FOR PURCHASE",
          country: "Unknown", creationDate: null, expirationDate: null, hostingProvider: "None (DNS Failure)",
          asn: "Unknown", nameservers: []
        },
        virusTotal: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0 },
        googleSafeBrowsing: { isSafe: true, threats: [] }
      };

      cache.set(cacheKey, { timestamp: Date.now(), data: result });
      return result;
    }

    const [reputation, dns, ssl] = await Promise.all([
      ReputationScanner.analyze(url),
      DNSAnalyzer.resolve(domain),
      SSLInspector.analyze(domain)
    ]);

    const whois = await WHOISAnalyzer.analyze(domain, dns.ipAddresses);
    const piracy = PiracyDetector.analyze(url, domain);
    const phishing = PhishingDetector.analyze(url, domain);

    // Scoring Logic (Requirement 4)
    // Phishing keywords → +40
    // Malware domain → +70
    // Piracy domain → +40
    // Suspicious WHOIS → +10
    // Domain age < 1 year → +10
    // No SSL certificate → +15
    // Typosquatting detection → +20

    let score = 0;
    const flags = [];

    if (phishing.score >= 40) {
        score += 40;
        flags.push("Phishing indicators detected");
    }
    
    if (reputation.score >= 70) {
        score += 70;
        flags.push("Confirmed Malware/Malicious source");
    } else if (reputation.score > 0) {
        score += 30;
    }

    if (piracy.detected) {
        score += piracy.score;
        flags.push(piracy.type);
    }

    if (whois.registrar === 'Unknown') {
        score += 10;
        flags.push("Suspicious WHOIS: Unknown Registrar");
    }

    if (whois.isRecent) {
        score += 10;
        flags.push("Recently Registered Domain (< 1 year)");
    }

    if (!ssl.valid) {
        score += 15;
        flags.push(`No valid SSL certificate (${ssl.status})`);
    }

    if (phishing.hasTyposquatting) {
        score += 20;
        flags.push("Possible Typosquatting Domain");
    }

    // Final Normalization
    score = Math.min(100, Math.max(0, score));

    // Scale: 0-20 SAFE, 21-50 SUSPICIOUS, 51-100 MALICIOUS
    let riskLevel = "SAFE";
    if (score > 50) riskLevel = "MALICIOUS";
    else if (score > 20) riskLevel = "SUSPICIOUS";

    const result = {
      threatScore: score,
      riskLevel,
      phishingProbability: score > 70 ? "Critical" : score > 50 ? "High" : score > 20 ? "Moderate" : "Low",
      issues: flags.length > 0 ? flags : ["No significant threats detected"],
      piracyStatus: piracy.detected ? piracy.type : "No Piracy Signals",
      sslStatus: {
        valid: ssl.valid,
        status: ssl.frontendStatus, // Matching frontend format "[ SECURE ]"
        actualStatus: ssl.status,  // For backend/report
        daysRemaining: ssl.daysRemaining,
        validFrom: ssl.validFrom,
        validTo: ssl.validTo
      },
      domainInfo: {
        age: whois.age,
        registrar: whois.registrar,
        country: whois.country,
        creationDate: whois.creationDate,
        expirationDate: whois.expirationDate,
        hostingProvider: whois.hostingProvider,
        asn: whois.asn,
        nameservers: dns.nameservers.slice(0, 4)
      },

      virusTotal: reputation.virusTotal,
      googleSafeBrowsing: reputation.googleSafeBrowsing
    };

    cache.set(cacheKey, { timestamp: Date.now(), data: result });
    return result;
  }
}

module.exports = ThreatEngine;
