const sslChecker = require('ssl-checker');
const tls = require('tls');

class SSLInspector {
  static async analyze(domain) {
    const cleanDomain = domain.split(':')[0];
    
    try {
      const ssl = await sslChecker(cleanDomain, { method: 'GET', port: 443, timeout: 10000 });
      
      let status = 'UNKNOWN';
      let frontendStatus = '[ INSECURE ]';

      if (ssl.valid) {
        if (ssl.daysRemaining <= 0) {
          status = 'EXPIRED';
        } else {
          status = 'VALID';
          frontendStatus = '[ SECURE ]';
        }
      } else {
        status = 'INVALID';
      }

      // Check for self-signed
      const selfSigned = await this.isSelfSigned(cleanDomain);
      if (selfSigned) {
          status = 'SELF-SIGNED';
          frontendStatus = '[ INSECURE ]';
      }

      return {
        valid: ssl.valid && status === 'VALID',
        status,
        frontendStatus,
        daysRemaining: ssl.daysRemaining || 0,
        validFrom: ssl.validFrom,
        validTo: ssl.validTo,
        score: (ssl.valid && status === 'VALID') ? 0 : 15
      };
    } catch (err) {
      return {
        valid: false,
        status: 'NO SSL',
        frontendStatus: '[ INSECURE ]',
        daysRemaining: 0,
        score: 15
      };
    }
  }

  static async isSelfSigned(domain) {
      return new Promise((resolve) => {
          const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
              const cert = socket.getPeerCertificate();
              if (cert && cert.issuer && cert.subject) {
                  // If issuer and subject are the same, it's likely self-signed
                  const isSelf = JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
                  socket.end();
                  resolve(isSelf);
              } else {
                  socket.end();
                  resolve(false);
              }
          });
          socket.on('error', () => resolve(false));
          setTimeout(() => {
              socket.destroy();
              resolve(false);
          }, 5000);
      });
  }
}

module.exports = SSLInspector;
