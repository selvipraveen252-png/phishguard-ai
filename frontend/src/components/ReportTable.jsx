import { useState } from 'react'

const RiskBadge = ({ level }) => {
  if (level === 'MALICIOUS') return <span className="badge badge-malicious"><span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse"></span> MALICIOUS</span>
  if (level === 'SUSPICIOUS') return <span className="badge badge-suspicious"><span className="w-1.5 h-1.5 rounded-full bg-cyber-yellow"></span> SUSPICIOUS</span>
  return <span className="badge badge-safe"><span className="w-1.5 h-1.5 rounded-full bg-cyber-green"></span> SAFE</span>
}

const SSLBadge = ({ status }) => {
  const isGood = status === 'VALID'
  const isBad = status === 'NO SSL' || status === 'INVALID' || status === 'EXPIRED'
  const color = isGood ? 'text-cyber-green' : isBad ? 'text-cyber-red' : 'text-gray-400'
  return <span className={`font-mono text-xs ${color}`}>{isGood ? '[ SECURE ]' : isBad ? '[ INSECURE ]' : '[ UNKNOWN ]'}</span>
}

const ScoreBar = ({ score }) => {
  const color = score > 50 ? 'bg-cyber-red' : score > 20 ? 'bg-cyber-yellow' : 'bg-cyber-green'
  return (
    <div className="flex items-center gap-3">
      <div className="w-16 h-1 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${score}%` }}></div>
      </div>
      <span className={`font-mono text-xs ${color.replace('bg-', 'text-')}`}>{score}/100</span>
    </div>
  )
}

export default function ReportTable({ scans }) {
  const [expanded, setExpanded] = useState(null)

  if (!scans || scans.length === 0) {
    return (
      <div className="p-12 text-center text-gray-500 font-mono text-sm">
        [ NO ACTIVITY DETECTED ]
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="soc-table">
        <thead>
          <tr>
            <th>TARGET URL</th>
            <th>DOMAIN</th>
            <th>THREAT SCORE</th>
            <th>RISK LEVEL</th>
            <th>SSL/TLS</th>
            <th>TIMESTAMP</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan, i) => {
            const isExpanded = expanded === scan._id
            return (
              <>
                <tr key={scan._id} className={isExpanded ? 'bg-gray-800/50' : ''}>
                  <td className="max-w-[200px]">
                    <span className="text-gray-300 font-mono text-xs truncate block" title={scan.url}>
                      {scan.url}
                    </span>
                  </td>
                  <td><span className="text-gray-400 font-mono text-xs">{scan.domain}</span></td>
                  <td><ScoreBar score={scan.threatScore || 0} /></td>
                  <td><RiskBadge level={scan.riskLevel} /></td>
                  <td><SSLBadge status={scan.sslStatus?.status} /></td>
                  <td className="text-gray-500 font-mono text-[10px]">
                    {new Date(scan.createdAt).toISOString().replace('T', ' ').slice(0, 19)}Z
                  </td>
                  <td>
                    <button 
                      onClick={() => setExpanded(isExpanded ? null : scan._id)}
                      className="text-cyber-cyan hover:text-white text-xs font-mono bg-cyber-cyan/10 hover:bg-cyber-cyan/20 px-2 py-1 rounded transition-colors"
                    >
                      {isExpanded ? '[-] HIDE' : '[+] VIEW'}
                    </button>
                  </td>
                </tr>
                {isExpanded && (
                  <tr className="bg-gray-900 border-b border-cyber-border">
                    <td colSpan={7} className="p-0">
                      <div className="p-4 grid grid-cols-1 md:grid-cols-4 gap-6 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTAgMGg0MHY0MEgwVjB6bTIwIDIwaDIwdjIwSDIwVjIwek0wIDIwaDIwdjIwSDBWMjB6IiBmaWxsPSIjM0IzQjRGIiBmaWxsLW9wYWNpdHk9IjAuMDUiIGZpbGwtcnVsZT0iZXZlbm9kZCIvPjwvc3ZnPg==')]">
                        
                        <div>
                          <p className="text-gray-500 text-[10px] uppercase font-mono mb-1">VirusTotal Intel</p>
                          <div className="flex items-center gap-2">
                            <span className={`font-mono text-sm ${scan.virusTotal?.malicious > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                              {scan.virusTotal?.malicious || 0}
                            </span>
                            <span className="text-gray-400 text-xs">engines flagged</span>
                          </div>
                        </div>

                        <div>
                          <p className="text-gray-500 text-[10px] uppercase font-mono mb-1">Google Safe Browsing</p>
                          <span className={`font-mono text-sm ${scan.googleSafeBrowsing?.isSafe ? 'text-cyber-green' : 'text-cyber-red'}`}>
                            {scan.googleSafeBrowsing?.isSafe ? 'CLEAN' : scan.googleSafeBrowsing?.threats?.join(', ') || 'FLAGGED'}
                          </span>
                        </div>

                        <div>
                          <p className="text-gray-500 text-[10px] uppercase font-mono mb-1">Domain Age</p>
                          <span className="font-mono text-sm text-gray-300">
                            {scan.domainInfo?.age != null ? `${scan.domainInfo.age} Days` : 'Unknown'}
                          </span>
                        </div>

                        <div className="md:col-span-4">
                          <p className="text-gray-500 text-[10px] uppercase font-mono mb-2">Detected Anomalies</p>
                          {scan.issues?.length > 0 ? (
                            <div className="flex flex-wrap gap-2">
                              {scan.issues.map((issue, idx) => (
                                <span key={idx} className="bg-cyber-red/10 border border-cyber-red/30 text-cyber-red px-2 py-1 rounded text-[10px] font-mono">
                                  {issue}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-cyber-green text-xs font-mono">NO ANOMALIES DETECTED</span>
                          )}
                        </div>

                      </div>
                    </td>
                  </tr>
                )}
              </>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
