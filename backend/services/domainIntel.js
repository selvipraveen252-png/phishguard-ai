const dns = require('dns').promises;
const whois = require('whois-json');
const axios = require('axios');

const { checkSSL } = require('./sslChecker');

/**
 * Check if a domain is active via DNS, HTTP, or SSL
 * A domain is ACTIVE if:
 * - DNS resolution succeeds
 * - OR HTTP response exists (status 200–499)
 * - OR SSL certificate is detected
 */
async function checkDomainAvailability(domain) {
  const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
  
  // 1. Check DNS resolution first (most efficient)
  try {
    // dns.lookup follows OS resolver - more reliable than resolve4 for general availability
    await dns.lookup(cleanDomain);
    return true;
  } catch (dnsErr) {
    // DNS failed, continue to other checks
  }

  // 2. Check HTTP status (200-499)
  try {
    // Use GET with 1 byte limit for better compatibility than HEAD (some sites block HEAD)
    const response = await axios.get(`http://${cleanDomain}`, { 
      timeout: 5000,
      validateStatus: (status) => status >= 200 && status < 500,
      maxContentLength: 1, // Only need status code
      maxRedirects: 5
    });
    return true;
  } catch (httpErr) {
    // If HTTP fails, try HTTPS specifically
    try {
      await axios.get(`https://${cleanDomain}`, {
        timeout: 5000,
        validateStatus: (status) => status >= 200 && status < 500,
        maxContentLength: 1,
        maxRedirects: 5
      });
      return true;
    } catch (httpsErr) {
      // Continue to SSL check
    }
  }

  // 3. Check SSL Certificate (Port 443)
  try {
    const ssl = await checkSSL(cleanDomain);
    // If status is not 'NO SSL', then something responded on port 443
    if (ssl && ssl.status !== 'NO SSL' && ssl.status !== 'UNKNOWN') {
      return true;
    }
  } catch (sslErr) {
    // Final failure
  }

  return false;
}

/**
 * Get WHOIS and DNS information for a domain
 * @param {string} domain - Domain to check
 * @returns {object} - Domain intelligence result
 */
async function getDomainIntel(domain) {
  const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
  
  const isActive = await checkDomainAvailability(cleanDomain);
  
  let whoisData = {};
  let dnsData = {};
  
  // WHOIS lookup
  try {
    const raw = await whois(cleanDomain, { timeout: 10000 });
    whoisData = raw;
  } catch (err) {
    console.warn(`⚠️ WHOIS failed for ${cleanDomain}:`, err.message);
  }

  // DNS lookup
  try {
    const [addresses, nameservers] = await Promise.allSettled([
      dns.resolve4(cleanDomain),
      dns.resolveNs(cleanDomain)
    ]);
    
    dnsData.ipAddresses = addresses.status === 'fulfilled' ? addresses.value : [];
    dnsData.nameservers = nameservers.status === 'fulfilled' ? nameservers.value : [];
  } catch (err) {
    console.warn(`⚠️ DNS lookup failed for ${cleanDomain}:`, err.message);
  }

  // Parse WHOIS data
  const registrar = extractWhoisField(whoisData, [
    'registrar', 'Registrar', 'REGISTRAR', 'Registrar Name'
  ]);

  const country = extractWhoisField(whoisData, [
    'registrantCountry', 'country', 'Country', 'Registrant Country'
  ]);

  const creationDateRaw = extractWhoisField(whoisData, [
    'creationDate', 'created', 'Created Date', 'Creation Date',
    'Domain Registration Date', 'registered'
  ]);

  const expirationDateRaw = extractWhoisField(whoisData, [
    'registrarRegistrationExpirationDate', 'expiresDate', 'Expiry Date',
    'Expiration Date', 'Registry Expiry Date', 'Registrar Registration Expiration Date'
  ]);

  const nameservers = whoisData.nameServer || whoisData.nameServers || 
    dnsData.nameservers || [];

  const nsArray = Array.isArray(nameservers) 
    ? nameservers 
    : typeof nameservers === 'string' 
      ? nameservers.split('\n').filter(Boolean)
      : [];

  // Calculate domain age
  let domainAge = null;
  let creationDate = null;
  
  if (creationDateRaw) {
    try {
      const parsed = new Date(creationDateRaw);
      if (!isNaN(parsed.getTime())) {
        creationDate = parsed.toISOString();
        const ageMs = Date.now() - parsed.getTime();
        domainAge = Math.floor(ageMs / (1000 * 60 * 60 * 24));
      }
    } catch (e) {
      // ignore parse errors
    }
  }

  let expirationDate = null;
  if (expirationDateRaw) {
    try {
      const parsed = new Date(expirationDateRaw);
      if (!isNaN(parsed.getTime())) {
        expirationDate = parsed.toISOString();
      }
    } catch (e) {
      // ignore
    }
  }

  // Determine hosting provider from IPs
  let hostingProvider = null;
  if (dnsData.ipAddresses && dnsData.ipAddresses.length > 0) {
    hostingProvider = await getHostingProvider(dnsData.ipAddresses[0]);
  }

  return {
    isActive,
    age: domainAge,
    registrar: registrar || 'Unknown',
    country: country || 'Unknown',
    creationDate,
    expirationDate,
    nameservers: nsArray.slice(0, 4),
    hostingProvider: hostingProvider || 'Unknown',
    ipAddresses: dnsData.ipAddresses || []
  };
}

function extractWhoisField(data, keys) {
  for (const key of keys) {
    if (data[key]) {
      const val = data[key];
      if (Array.isArray(val)) return val[0];
      if (typeof val === 'string') return val.trim();
    }
  }
  return null;
}

/**
 * Get IP intelligence for a domain with fallbacks
 * @param {string} domain 
 * @returns {object}
 */
async function getIPIntelligence(domain) {
  try {
    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    
    let ip = null;
    try {
      const lookup = await dns.lookup(cleanDomain);
      ip = lookup.address;
    } catch (dnsErr) {
      const addresses = await dns.resolve4(cleanDomain).catch(() => []);
      if (addresses.length > 0) {
        ip = addresses[0];
      }
    }
    
    if (!ip) {
      throw new Error('Could not resolve domain to IP Address');
    }
    
    // Attempt multiple APIs for reliability
    const apis = [
      { url: `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_API_KEY}`, parse: d => ({ ip: d.ip, country: d.country, region: d.region, city: d.city, org: d.org, asn: d.asn || (d.org?.startsWith('AS') ? d.org.split(' ')[0] : 'Unknown') }) },
      { url: `https://ipapi.co/${ip}/json/`, parse: d => ({ ip: d.ip, country: d.country_code, region: d.region, city: d.city, org: d.org, asn: d.asn }) },
      { url: `https://ipwhois.app/json/${ip}`, parse: d => ({ ip: d.ip, country: d.country_code, region: d.region, city: d.city, org: d.org || d.isp, asn: d.asn }) }
    ];

    for (const api of apis) {
      try {
        const res = await axios.get(api.url, { timeout: 4000 });
        if (res.data && (res.data.ip || res.data.success !== false)) {
          return api.parse(res.data);
        }
      } catch (e) {
        continue;
      }
    }

    return {
      ip,
      country: 'Unknown',
      region: 'Unknown',
      city: 'Unknown',
      org: 'Unknown',
      asn: 'Unknown'
    };
  } catch (err) {
    throw new Error(`IP Intelligence lookup failed: ${err.message}`);
  }
}


async function getHostingProvider(ip) {
  try {
    const response = await axios.get(`https://ipinfo.io/${ip}/json`, { timeout: 5000 });
    return response.data.org || response.data.company?.name || null;
  } catch (e) {
    return null;
  }
}

module.exports = { getDomainIntel, getIPIntelligence };
