const dns = require('dns').promises;

class DNSAnalyzer {
  static async resolve(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const results = {
      ipAddresses: [],
      nameservers: [],
      mxRecords: [],
      txtRecords: []
    };

    try {
      const [a, ns, mx, txt] = await Promise.allSettled([
        dns.resolve4(cleanDomain),
        dns.resolveNs(cleanDomain),
        dns.resolveMx(cleanDomain),
        dns.resolveTxt(cleanDomain)
      ]);

      if (a.status === 'fulfilled') results.ipAddresses = a.value;
      if (ns.status === 'fulfilled') results.nameservers = ns.value;
      if (mx.status === 'fulfilled') results.mxRecords = mx.value;
      if (txt.status === 'fulfilled') results.txtRecords = txt.value;

    } catch (err) {
      console.warn(`DNS Analysis warning for ${domain}:`, err.message);
    }

    return results;
  }

  static async checkExistence(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    try {
      await dns.lookup(cleanDomain);
      return { exists: true };
    } catch (err) {
      return { 
        exists: false, 
        error: err.code,
        isNXDOMAIN: ['ENOTFOUND', 'EAI_AGAIN'].includes(err.code)
      };
    }
  }
}

module.exports = DNSAnalyzer;
