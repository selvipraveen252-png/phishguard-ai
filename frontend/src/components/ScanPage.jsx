import { useState, useRef } from 'react'
import { scanUrl, getIPIntelligence } from '../services/api'
import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'

const ThreatGauge = ({ score }) => {
  const color = score > 60 ? '#EF4444' : score > 25 ? '#F59E0B' : '#22C55E'
  const offset = 251.3 - (score / 100) * 251.3

  return (
    <div className="relative w-40 h-40 flex items-center justify-center">
      {/* Background circle */}
      <svg className="w-full h-full transform -rotate-90">
        <circle cx="80" cy="80" r="40" stroke="#1F2937" strokeWidth="8" fill="none" />
        {/* Animated score circle */}
        <circle
          cx="80"
          cy="80"
          r="40"
          stroke={color}
          strokeWidth="8"
          fill="none"
          strokeDasharray="251.3"
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-4xl font-mono font-bold`} style={{ color }}>{score}</span>
        <span className="text-[10px] text-gray-500 font-mono tracking-widest uppercase mt-1">Threat Score</span>
      </div>
    </div>
  )
}

export default function ScanPage() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const reportRef = useRef(null)

  const handleScan = async (e) => {
    e.preventDefault()
    if (!url.trim()) return

    setScanning(true)
    setResult(null)
    setError(null)

    try {
      const res = await scanUrl(url.trim())
      setResult(res.data)
      
      // Fetch IP Intelligence
      try {
        const ipData = await getIPIntelligence(res.data.domain)
        setResult(prev => ({ ...prev, ipIntel: ipData }))
      } catch (ipErr) {
        console.warn('IP Intelligence fetch failed', ipErr)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const downloadReport = async () => {
    if (!reportRef.current || !result) return
    
    // Temporarily hide the download button to prevent it from showing in the PDF
    const btn = document.getElementById('dl-btn')
    if (btn) btn.style.display = 'none'

    try {
      const canvas = await html2canvas(reportRef.current, {
        scale: 2,
        backgroundColor: '#0B1220',
        logging: false
      })
      
      const imgData = canvas.toDataURL('image/png')
      const pdf = new jsPDF('p', 'mm', 'a4')
      const pdfWidth = pdf.internal.pageSize.getWidth()
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight)
      pdf.save(`${result.domain}-security-report.pdf`)
    } catch (e) {
      console.error('PDF generation failed', e)
    } finally {
      if (btn) btn.style.display = 'flex'
    }
  }

  const riskClass = result?.riskLevel === 'HIGH RISK' ? 'red' 
                  : result?.riskLevel === 'SUSPICIOUS' ? 'yellow' 
                  : 'green'

  return (
    <div className="space-y-6 animate-fade-in relative z-10">
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-white">INTELLIGENCE SCANNER</h2>
        <p className="text-gray-400 font-mono text-xs mt-1">ANALYZE URLS AGAINST THREAT DATABASES AND AI HEURISTICS</p>
      </div>

      {/* Input */}
      <div className="soc-card p-6 border-t-2 border-t-cyber-cyan">
        <form onSubmit={handleScan} className="flex gap-4">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="[ ENTER TARGET URL : HTTPS://... ]"
            className="input-soc font-mono"
            disabled={scanning}
          />
          <button type="submit" className="btn-primary flex items-center gap-3 min-w-[200px] justify-center" disabled={scanning || !url.trim()}>
            {scanning ? (
              <>
                <span className="w-4 h-4 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></span>
                <span className="font-mono tracking-wider">ANALYZING...</span>
              </>
            ) : (
              <>
                <span className="text-xl">⌕</span>
                <span className="font-mono tracking-wider">INITIATE SCAN</span>
              </>
            )}
          </button>
        </form>
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red text-cyber-red px-4 py-3 rounded-lg font-mono text-sm">
          [ SCAN FAILED ] {error}
        </div>
      )}

      {/* Report View */}
      {result && (
        <div ref={reportRef} className="soc-card mt-8 p-8 overflow-hidden relative">
          {/* Decorative background grid for PDF */}
          <div className="absolute inset-0 bg-grid opacity-30 pointer-events-none"></div>
          
          <div className="relative z-10 flex justify-between items-start mb-8 border-b border-cyber-border pb-6">
            <div>
              <h1 className="text-3xl font-bold text-white tracking-widest uppercase mb-2">SECURITY REPORT</h1>
              <div className="flex flex-col gap-1 font-mono text-sm">
                <span className="text-gray-400">TARGET DOMAIN: <span className="text-cyber-cyan">{result.domain}</span></span>
                <span className="text-gray-500">ANALYSIS DATE: {new Date(result.createdAt).toUTCString()}</span>
              </div>
            </div>
            <button 
              id="dl-btn"
              onClick={downloadReport} 
              className="btn-primary bg-gray-800 hover:bg-gray-700 border-gray-600 shadow-none flex items-center gap-2"
            >
              <span className="text-lg">↓</span> <span className="font-mono">DOWNLOAD PDF</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 relative z-10">
            
            {/* 1. Website Risk Overview */}
            <div className={`p-6 bg-gray-900/50 rounded-xl border border-cyber-${riskClass}/30 relative overflow-hidden`}>
              <div className={`absolute top-0 left-0 w-1 h-full bg-cyber-${riskClass}`}></div>
              <h3 className="text-gray-400 font-mono text-xs uppercase tracking-widest mb-6">1. RISK OVERVIEW</h3>
              
              <div className="flex items-center justify-between">
                <ThreatGauge score={result.threatScore} />
                <div className="space-y-4 flex-1 ml-8">
                  <div>
                    <span className="block text-gray-500 font-mono text-[10px] uppercase mb-1">Risk Classification</span>
                    <span className={`badge badge-${result.riskLevel === 'HIGH RISK' ? 'high-risk' : result.riskLevel.toLowerCase()}`}>
                      {result.riskLevel}
                    </span>
                  </div>
                  <div>
                    <span className="block text-gray-500 font-mono text-[10px] uppercase mb-1">Phishing Probability</span>
                    <span className="text-white font-mono text-lg">{result.phishingProbability?.toUpperCase()}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Detected Security Issues */}
            <div className="p-6 bg-gray-900/50 rounded-xl border border-cyber-border">
              <h3 className="text-gray-400 font-mono text-xs uppercase tracking-widest mb-6">2. THREAT SIGNATURES</h3>
              {result.issues && result.issues.length > 0 ? (
                <ul className="space-y-3">
                  {result.issues.map((issue, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <span className="text-cyber-red mt-1 text-xs">►</span>
                      <span className="text-gray-300 font-mono text-sm">{issue}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="flex items-center gap-3 text-cyber-green font-mono text-sm h-full">
                  <span className="text-xl">✓</span>
                  <span>NO THREAT SIGNATURES MATCHED</span>
                </div>
              )}
            </div>

            {/* 3. Phishing Indicators */}
            <div className="p-6 bg-gray-900/50 rounded-xl border border-cyber-border">
              <h3 className="text-gray-400 font-mono text-xs uppercase tracking-widest mb-6">3. ENGINE INTEL</h3>
              <div className="space-y-4 font-mono text-sm">
                <div className="flex justify-between items-center pb-2 border-b border-gray-800">
                  <span className="text-gray-500">Google Safe Browsing</span>
                  <span className={result.googleSafeBrowsing?.isSafe ? 'text-cyber-green' : 'text-cyber-red'}>
                    {result.googleSafeBrowsing?.isSafe ? '[ CLEAN ]' : '[ FLAGGED ]'}
                  </span>
                </div>
                <div className="flex justify-between items-center pb-2 border-b border-gray-800">
                  <span className="text-gray-500">VirusTotal Malicious</span>
                  <span className={result.virusTotal?.malicious > 0 ? 'text-cyber-red' : 'text-cyber-green'}>
                    {result.virusTotal?.malicious} ENGINES
                  </span>
                </div>
                <div className="flex justify-between items-center pb-2 border-b border-gray-800">
                  <span className="text-gray-500">VirusTotal Suspicious</span>
                  <span className={result.virusTotal?.suspicious > 0 ? 'text-cyber-yellow' : 'text-cyber-green'}>
                    {result.virusTotal?.suspicious} ENGINES
                  </span>
                </div>
              </div>
            </div>

            {/* 4. Domain Intelligence Summary */}
            <div className="p-6 bg-gray-900/50 rounded-xl border border-cyber-border">
              <h3 className="text-gray-400 font-mono text-xs uppercase tracking-widest mb-6">4. DOMAIN RECONNAISSANCE</h3>
              <div className="grid grid-cols-2 gap-x-4 gap-y-4 font-mono text-xs">
                <div>
                  <span className="block text-gray-500 text-[10px] uppercase mb-1">Registrar</span>
                  <span className="text-gray-300 truncate block">{result.domainInfo?.registrar || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="block text-gray-500 text-[10px] uppercase mb-1">Domain Age</span>
                  <span className="text-gray-300">{result.domainInfo?.age != null ? `${result.domainInfo.age} DAYS` : 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="block text-gray-500 text-[10px] uppercase mb-1">Country</span>
                  <span className="text-gray-300">{result.domainInfo?.country || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="block text-gray-500 text-[10px] uppercase mb-1">SSL Certificate</span>
                  <span className={result.sslStatus?.valid ? 'text-cyber-green' : 'text-cyber-red'}>
                    {result.sslStatus?.status || 'UNKNOWN'}
                  </span>
                </div>
              </div>
            </div>

            {/* 5. IP Intelligence */}
            {result.ipIntel && (
              <div className="p-6 bg-gray-900/50 rounded-xl border border-cyber-border relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-cyber-cyan/5 rounded-full blur-2xl group-hover:bg-cyber-cyan/10 transition-all"></div>
                <h3 className="text-gray-400 font-mono text-xs uppercase tracking-widest mb-6">5. IP INTELLIGENCE</h3>
                <div className="grid grid-cols-2 gap-x-4 gap-y-4 font-mono text-[11px]">
                  <div>
                    <span className="block text-gray-500 text-[9px] uppercase mb-1">IP Address</span>
                    <span className="text-cyber-cyan font-bold">{result.ipIntel.ip}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[9px] uppercase mb-1">Location</span>
                    <div className="flex items-center gap-2 text-gray-300">
                      {result.ipIntel.country && (
                        <img 
                          src={`https://flagcdn.com/w20/${result.ipIntel.country.toLowerCase()}.png`} 
                          alt={result.ipIntel.country}
                          className="w-4 h-3 opacity-80"
                        />
                      )}
                      <span>{result.ipIntel.city}, {result.ipIntel.region}</span>
                    </div>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[9px] uppercase mb-1">ISP / Organization</span>
                    <span className="text-gray-400 truncate block" title={result.ipIntel.org}>{result.ipIntel.org}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[9px] uppercase mb-1">Network (ASN)</span>
                    <span className="text-white bg-gray-800 px-2 py-0.5 rounded border border-gray-700">
                      {result.ipIntel.asn}
                    </span>
                  </div>
                </div>
              </div>
            )}

          </div>
        </div>
      )}
    </div>
  )
}
