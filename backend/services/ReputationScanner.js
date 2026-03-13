const { checkGoogleSafeBrowsing } = require('./googleSafeBrowsing');
const { checkVirusTotal } = require('./virusTotal');

class ReputationScanner {
  static async analyze(url) {
    const [gsb, vt] = await Promise.all([
      checkGoogleSafeBrowsing(url).catch(() => ({ isSafe: true, threats: [] })),
      checkVirusTotal(url).catch(() => ({ malicious: 0, suspicious: 0 }))
    ]);

    let score = 0;
    const flags = [];

    if (!gsb.isSafe) {
      score += 85; // Very high, but we'll cap at 100 later
      flags.push("Blacklisted by Google Safe Browsing");
    }

    if (vt.malicious > 0) {
      score += Math.min(70, vt.malicious * 15);
      flags.push(`${vt.malicious} engines flagged as Malicious on VirusTotal`);
    }

    return {
      googleSafeBrowsing: gsb,
      virusTotal: vt,
      score,
      flags
    };
  }
}

module.exports = ReputationScanner;
