/**
 * Detect piracy-related keywords in a URL or domain
 * @param {string} url - The URL to check
 * @returns {string} - "High Piracy Risk", "Possible Piracy", or "No Piracy Signals"
 */
function detectPiracy(url) {
  if (!url) return "No Piracy Signals";
  const lowerUrl = url.toLowerCase();
  
  // LAYER 1 — TRUSTED DOMAIN WHITELIST
  const trustedDomains = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", 
    "twitter.com", "linkedin.com", "wikipedia.org", "github.com", 
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", 
    "openai.com", "stackoverflow.com", "reddit.com", "cloudflare.com", 
    "mozilla.org", "bing.com", "yahoo.com", "zoom.us", "figma.com", "notion.so"
  ];

  if (trustedDomains.some(d => lowerUrl.includes(d))) {
    return "No Piracy Signals";
  }

  // Extract domain part
  let domain = "";
  try {
    const urlObj = new URL(lowerUrl.startsWith('http') ? lowerUrl : `http://${lowerUrl}`);
    domain = urlObj.hostname.replace(/^www\./, '');
  } catch (e) {
    domain = lowerUrl;
  }

  // LAYER 3 — PIRACY INTELLIGENCE DATABASE
  const piracyDatabase = [
    "fitgirl-repacks.site", "dodi-repacks.site", "steamunlocked.net",
    "skidrowcodex.net", "oceanofgames.com", "igg-games.com",
    "apunkagames.net", "thepiratebay.org", "1337x.to", "rarbg.to",
    "yts.mx", "limetorrents.info", "torrentz2.eu", "tamilrockers.ws",
    "tamilblasters.site", "moviesda.red", "gogoanime.ai", "9anime.to",
    "aniwatch.to", "soap2day.rs", "putlocker.pe", "fmovies.to", "myflixer.to"
  ];

  if (piracyDatabase.some(pd => domain === pd || domain.endsWith(`.${pd}`))) {
    return "High Piracy Risk";
  }

  // LAYER 7 — PIRACY KEYWORD DETECTION
  const piracyKeywords = [
    "fitgirl", "repack", "torrent", "crack", "warez",
    "camrip", "dvdrip", "hdrip", "free-movie", "movie-download",
    "anime-download", "watch-free", "free-anime", "stream-anime"
  ];

  const foundKeywords = piracyKeywords.some(kw => lowerUrl.includes(kw));

  // LAYER 8 — SUSPICIOUS TLD DETECTION
  const riskyTLDs = [".to", ".sx", ".cx", ".site", ".download", ".stream", ".games", ".ru"];
  const isRiskyTLD = riskyTLDs.some(tld => domain.endsWith(tld));

  if (foundKeywords && isRiskyTLD) {
    return "High Piracy Risk";
  }

  if (foundKeywords || isRiskyTLD) {
    return "Possible Piracy";
  }

  return "No Piracy Signals";
}

module.exports = { detectPiracy };
