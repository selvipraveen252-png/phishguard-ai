const dns = require('dns').promises;
const whois = require('whois-json');
const axios = require('axios');

/**
 * Get WHOIS and DNS information for a domain
 * @param {string} domain - Domain to check
 * @returns {object} - Domain intelligence result
 */
async function getDomainIntel(domain) {
  const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
  
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
 * Get IP intelligence for a domain
 * @param {string} domain 
 * @returns {object}
 */
async function getIPIntelligence(domain) {
  try {
    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    
    let ip = null;
    try {
      // dns.lookup follows the OS resolver logic
      const lookup = await dns.lookup(cleanDomain);
      ip = lookup.address;
    } catch (dnsErr) {
      // Fallback to direct DNS resolution
      const addresses = await dns.resolve4(cleanDomain).catch(() => []);
      if (addresses.length > 0) {
        ip = addresses[0];
      }
    }
    
    if (!ip) {
      throw new Error('Could not resolve domain to IP Address');
    }
    
    const token = process.env.IPINFO_API_KEY;
    const response = await axios.get(`https://ipinfo.io/${ip}?token=${token}`, { timeout: 10000 });
    const data = response.data;
    
    // IPinfo's org often contains ASN like "AS15169 Google LLC"
    let asn = data.asn;
    if (!asn && data.org && data.org.startsWith('AS')) {
      asn = data.org.split(' ')[0];
    }

    return {
      ip: data.ip || ip,
      country: data.country || 'Unknown',
      region: data.region || 'Unknown',
      city: data.city || 'Unknown',
      org: data.org || 'Unknown',
      asn: asn || 'Unknown'
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
