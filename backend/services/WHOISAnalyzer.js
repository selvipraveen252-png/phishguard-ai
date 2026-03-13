const whois = require('whois-json');
const axios = require('axios');

class WHOISAnalyzer {
  static async analyze(domain, ipAddresses) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    let data = {};
    
    try {
      data = await whois(cleanDomain, { timeout: 10000 });
    } catch (err) {
      console.warn(`WHOIS failed for ${cleanDomain}:`, err.message);
    }

    const registrar = this.extractField(data, ['registrar', 'Registrar', 'REGISTRAR', 'Registrar Name']);
    const country = this.extractField(data, ['registrantCountry', 'country', 'Country', 'Registrant Country']);
    const creationDateRaw = this.extractField(data, ['creationDate', 'created', 'Created Date', 'Creation Date', 'registered']);
    const expirationDateRaw = this.extractField(data, ['registrarRegistrationExpirationDate', 'expiresDate', 'Expiry Date', 'Expiration Date']);

    let age = null;
    let creationDate = null;
    if (creationDateRaw) {
      const parsed = new Date(creationDateRaw);
      if (!isNaN(parsed.getTime())) {
        creationDate = parsed.toISOString();
        const ageMs = Date.now() - parsed.getTime();
        age = Math.floor(ageMs / (1000 * 60 * 60 * 24));
      }
    }

    let hostingProvider = 'Unknown';
    let asn = 'Unknown';
    if (ipAddresses && ipAddresses.length > 0) {
      const hostData = await this.getHostingProvider(ipAddresses[0]);
      hostingProvider = hostData.name;
      asn = hostData.asn;
    }

    // Cloudflare detection
    if (hostingProvider.toLowerCase().includes('cloudflare') || 
        (data.nameServer && JSON.stringify(data.nameServer).toLowerCase().includes('cloudflare'))) {
      hostingProvider = 'Cloudflare CDN Protected';
    }

    return {
      registrar: registrar || 'Unknown',
      country: country || 'Unknown',
      creationDate,
      expirationDate: expirationDateRaw ? new Date(expirationDateRaw).toISOString() : null,
      age,
      hostingProvider,
      asn,
      isRecent: age !== null && age < 365,
      score: (age !== null && age < 365 ? 10 : 0) + (registrar === 'Unknown' ? 10 : 0)
    };
  }

  static extractField(data, keys) {
    for (const key of keys) {
      if (data[key]) {
        const val = data[key];
        return Array.isArray(val) ? val[0] : typeof val === 'string' ? val.trim() : val;
      }
    }
    return null;
  }

  static async getHostingProvider(ip) {
    const apis = [
      { url: `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_API_KEY}`, parse: d => ({ name: d.org, asn: d.asn || (d.org?.startsWith('AS') ? d.org.split(' ')[0] : 'Unknown') }) },
      { url: `https://ipapi.co/${ip}/json/`, parse: d => ({ name: d.org, asn: d.asn }) },
      { url: `https://ipwhois.app/json/${ip}`, parse: d => ({ name: d.org || d.isp, asn: d.asn }) }
    ];

    for (const api of apis) {
      try {
        const res = await axios.get(api.url, { timeout: 3000 });
        const provider = api.parse(res.data);
        if (provider.name) return provider;
      } catch (e) {
        continue;
      }
    }
    return { name: 'Unknown', asn: 'Unknown' };
  }

  static async checkRegistration(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    try {
      const data = await whois(cleanDomain, { timeout: 5000 });
      
      // Different WHOIS servers return different strings for "not found"
      const statusStr = JSON.stringify(data).toLowerCase();
      const isUnregistered = 
        statusStr.includes("no match") || 
        statusStr.includes("not found") || 
        statusStr.includes("available") ||
        Object.keys(data).length <= 1;

      return {
        isRegistered: !isUnregistered,
        data: data
      };
    } catch (err) {
      return { isRegistered: false, error: err.message };
    }
  }
}

module.exports = WHOISAnalyzer;
