import { useState } from 'react'
import { getDomainInfo, getIPIntelligence } from '../services/api'

const TerminalRow = ({ label, value, highlight }) => (
  <div className="flex items-start mb-2 group">
    <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border group-hover:before:text-cyber-cyan transition-colors">
      {label}
    </span>
    <span className={`${highlight ? 'text-cyber-cyan' : 'text-gray-300'} break-all`}>
      {value || '[ NO DATA OBFUSCATED ]'}
    </span>
  </div>
)

export default function DomainInfo() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [ipIntel, setIpIntel] = useState(null)
  const [error, setError] = useState(null)

  const handleLookup = async (e) => {
    e.preventDefault()
    const d = domain.trim().replace(/^https?:\/\//, '').split('/')[0]
    if (!d) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const [res, ipRes] = await Promise.all([
        getDomainInfo(d),
        getIPIntelligence(d).catch(err => {
          console.warn('IP Intel failed:', err.message);
          return null;
        })
      ])
      setResult(res.data)
      setIpIntel(ipRes)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6 animate-fade-in relative z-10">
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-white">DOMAIN RECONNAISSANCE</h2>
        <p className="text-gray-400 font-mono text-xs mt-1">GATHER WHOIS, DNS, AND SSL INTELLIGENCE ON A TARGET DOMAIN</p>
      </div>

      <div className="soc-card p-6 border-t-2 border-t-cyber-cyan">
        <form onSubmit={handleLookup} className="flex gap-4">
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="[ ENTER TARGET DOMAIN ]"
            className="input-soc font-mono"
            disabled={loading}
          />
          <button type="submit" className="btn-primary min-w-[200px]" disabled={loading || !domain.trim()}>
            {loading ? (
              <span className="font-mono flex items-center justify-center gap-3">
                <span className="w-4 h-4 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></span>
                EXTRACTING...
              </span>
            ) : (
              <span className="font-mono tracking-wider">INITIATE RECON</span>
            )}
          </button>
        </form>
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red text-cyber-red px-4 py-3 rounded-lg font-mono text-sm">
          [ RECON FAILED ] {error}
        </div>
      )}

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-slide-up">
          {/* WHOIS DATA */}
          <div className="soc-card p-6">
            <h3 className="text-cyber-cyan font-mono text-sm uppercase tracking-widest mb-4 border-b border-cyber-border pb-2 inline-block">
              // WHOIS REGISTRATION DATA
            </h3>
            <div className="font-mono text-xs space-y-3 mt-4">
              <TerminalRow label="TARGET" value={result.domain} highlight />
              <TerminalRow label="REGISTRAR" value={result.registrar} />
              <TerminalRow label="REGISTRANT COUNTRY" value={result.country} />
              <TerminalRow label="DOMAIN AGE" value={result.domainAge != null ? `${result.domainAge} DAYS` : null} />
              <TerminalRow 
                label="CREATION DATE" 
                value={result.creationDate ? new Date(result.creationDate).toISOString().split('T')[0] : null} 
              />
              <TerminalRow 
                label="EXPIRATION DATE" 
                value={result.expirationDate ? new Date(result.expirationDate).toISOString().split('T')[0] : null} 
              />
            </div>
            
            {/* IP INTELLIGENCE */}
            {ipIntel && (
              <div className="soc-card p-6 border-t border-cyber-cyan/30">
                <h3 className="text-cyber-cyan font-mono text-sm uppercase tracking-widest mb-4 border-b border-cyber-border pb-2 inline-block">
                  // IP INTELLIGENCE & GEOLOCATION
                </h3>
                <div className="font-mono text-xs space-y-3 mt-4">
                  <TerminalRow label="IP ADDRESS" value={ipIntel.ip} highlight />
                  <div className="flex items-start mb-2 group">
                    <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border">COUNTRY</span>
                    <span className="text-gray-300 flex items-center gap-2">
                      {ipIntel.country && (
                        <img 
                          src={`https://flagcdn.com/w20/${ipIntel.country.toLowerCase()}.png`} 
                          alt={ipIntel.country}
                          className="w-4 h-3 opacity-80"
                          onError={(e) => e.target.style.display = 'none'}
                        />
                      )}
                      {ipIntel.country}
                    </span>
                  </div>
                  <TerminalRow label="REGION" value={ipIntel.region} />
                  <TerminalRow label="CITY" value={ipIntel.city} />
                  <TerminalRow label="ISP / ORG" value={ipIntel.org} />
                  <div className="flex items-start mb-2 group">
                    <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border">ASN NETWORK</span>
                    <span className="text-cyber-cyan font-bold bg-cyber-cyan/10 px-2 py-0.5 rounded">
                      {ipIntel.asn || 'UNKNOWN'}
                    </span>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* INFRASTRUCTURE DATA */}
          <div className="space-y-6">
            
            {/* SSL */}
            <div className="soc-card p-6">
              <h3 className="text-cyber-cyan font-mono text-sm uppercase tracking-widest mb-4 border-b border-cyber-border pb-2 inline-block">
                // SSL/TLS HANDSHAKE
              </h3>
              <div className="font-mono text-xs space-y-3 mt-4">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border">CERTIFICATE STATUS</span>
                  <span className={`px-2 py-0.5 rounded ${result.ssl?.valid ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/50' : 'bg-cyber-red/20 text-cyber-red border border-cyber-red/50'}`}>
                    {result.ssl?.status}
                  </span>
                </div>
                {result.ssl?.daysRemaining > 0 && (
                  <TerminalRow label="DAYS REMAINING" value={result.ssl.daysRemaining} />
                )}
                {result.ssl?.validFrom && (
                  <TerminalRow label="ISSUED AT" value={new Date(result.ssl.validFrom).toISOString().split('T')[0]} />
                )}
                {result.ssl?.validTo && (
                  <TerminalRow label="EXPIRES AT" value={new Date(result.ssl.validTo).toISOString().split('T')[0]} />
                )}
              </div>
            </div>

            {/* DNS */}
            <div className="soc-card p-6">
              <h3 className="text-cyber-cyan font-mono text-sm uppercase tracking-widest mb-4 border-b border-cyber-border pb-2 inline-block">
                // DNS & NETWORK MAP
              </h3>
              <div className="font-mono text-xs space-y-3 mt-4">
                <TerminalRow label="HOSTING PROVIDER" value={result.hostingProvider} highlight />
                
                {result.ipAddresses?.length > 0 && (
                  <div className="flex items-start mt-4">
                    <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border">RESOLVED IP(s)</span>
                    <div className="flex flex-col gap-1">
                      {result.ipAddresses.map((ip, i) => (
                        <span key={i} className="text-gray-300 bg-gray-800/50 px-2 py-1 rounded inline-block w-fit">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {result.nameservers?.length > 0 && (
                  <div className="flex items-start mt-4">
                    <span className="text-gray-500 w-48 shrink-0 flex items-center before:content-['>'] before:mr-2 before:text-cyber-border">NAME SERVERS</span>
                    <div className="flex flex-col gap-1">
                      {result.nameservers.slice(0, 4).map((ns, i) => (
                        <span key={i} className="text-gray-400">
                          - {ns}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  )
}
