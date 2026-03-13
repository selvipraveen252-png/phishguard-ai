import { useEffect, useState, useCallback } from 'react'
import { Line, Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, ArcElement, Filler
} from 'chart.js'
import { getDashboard } from '../services/api'
import ReportTable from './ReportTable'

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  Title, Tooltip, Legend, ArcElement, Filler
)

const StatCard = ({ title, value, subtitle, icon, colorClass, glowClass }) => (
  <div className={`soc-card p-6 relative overflow-hidden group hover:border-${colorClass} ${glowClass}`}>
    <div className={`absolute -right-6 -top-6 w-24 h-24 rounded-full bg-${colorClass}/5 group-hover:bg-${colorClass}/10 transition-colors blur-xl`}></div>
    <div className="flex justify-between items-start relative z-10">
      <div>
        <p className="text-gray-400 text-xs font-mono uppercase tracking-widest mb-2">{title}</p>
        <p className={`text-4xl font-mono font-bold text-${colorClass}`}>{value ?? '—'}</p>
        {subtitle && <p className="text-gray-500 text-xs mt-2 font-mono">{subtitle}</p>}
      </div>
      <div className={`text-2xl text-${colorClass} bg-${colorClass}/10 p-3 rounded-lg border border-${colorClass}/20`}>
        {icon}
      </div>
    </div>
  </div>
)

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true)
      const res = await getDashboard()
      setData(res.data)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadDashboard()
    const interval = setInterval(loadDashboard, 30000)
    return () => clearInterval(interval)
  }, [loadDashboard])

  const lineChartData = {
    labels: data?.chartData?.labels || [],
    datasets: [
      {
        label: 'Total Scans',
        data: data?.chartData?.scans || [],
        borderColor: '#06B6D4',
        backgroundColor: 'rgba(6, 182, 212, 0.1)',
        borderWidth: 2,
        tension: 0.3,
        fill: true,
        pointBackgroundColor: '#06B6D4',
        pointBorderColor: '#111827',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
      {
        label: 'Malicious',
        data: data?.chartData?.highRisk || [],
        borderColor: '#EF4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 2,
        tension: 0.3,
        fill: true,
        pointBackgroundColor: '#EF4444',
        pointBorderColor: '#111827',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      }
    ]
  }

  const doughnutData = {
    labels: ['Safe', 'Suspicious', 'Malicious'],
    datasets: [
      {
        data: [
          data?.threatDistribution?.['SAFE'] || 0,
          data?.threatDistribution?.['SUSPICIOUS'] || 0,
          data?.threatDistribution?.['MALICIOUS'] || 0,
        ],
        backgroundColor: ['rgba(34, 197, 94, 0.8)', 'rgba(245, 158, 11, 0.8)', 'rgba(239, 68, 68, 0.8)'],
        borderColor: ['#22C55E', '#F59E0B', '#EF4444'],
        borderWidth: 1,
        hoverOffset: 4
      }
    ]
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    color: '#9CA3AF',
    plugins: {
      legend: { labels: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 11 }, boxWidth: 12, usePointStyle: true } },
      tooltip: {
        backgroundColor: '#111827',
        titleColor: '#F3F4F6',
        bodyColor: '#D1D5DB',
        borderColor: '#374151',
        borderWidth: 1,
        titleFont: { family: 'JetBrains Mono' },
        bodyFont: { family: 'JetBrains Mono' },
        padding: 12,
        cornerRadius: 8
      }
    },
    scales: {
      x: { grid: { color: 'rgba(31, 41, 55, 0.5)' }, ticks: { color: '#6B7280', font: { family: 'JetBrains Mono', size: 10 } } },
      y: { grid: { color: 'rgba(31, 41, 55, 0.5)' }, ticks: { color: '#6B7280', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 } }
    }
  }

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '75%',
    plugins: {
      legend: { position: 'bottom', labels: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 11 }, usePointStyle: true, padding: 20 } },
      tooltip: {
        backgroundColor: '#111827',
        titleColor: '#F3F4F6',
        bodyColor: '#D1D5DB',
        borderColor: '#374151',
        borderWidth: 1,
        titleFont: { family: 'JetBrains Mono' },
        bodyFont: { family: 'JetBrains Mono' }
      }
    }
  }

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-cyber-cyan font-mono animate-pulse">
        <div className="text-4xl">◱</div>
        <p>INITIALIZING DASHBOARD...</p>
      </div>
    )
  }

  const safePercent = (data?.safeDomains && data.totalScans) ? Math.round((data.safeDomains / data.totalScans) * 100) : 0

  return (
    <div className="space-y-6 animate-fade-in relative z-10">
      <div className="flex justify-between items-end border-b border-cyber-border pb-4">
        <div>
          <h2 className="text-2xl font-bold tracking-wide text-white">SOC OVERVIEW</h2>
          <p className="text-gray-400 font-mono text-xs mt-1">REAL-TIME THREAT INTELLIGENCE FEED</p>
        </div>
        <button onClick={loadDashboard} className="text-cyber-cyan border border-cyber-cyan/30 bg-cyber-cyan/5 hover:bg-cyber-cyan/10 px-4 py-1.5 rounded text-xs font-mono transition-colors">
          [ REFRESH DATA ]
        </button>
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red text-cyber-red px-4 py-3 rounded-lg font-mono text-sm">
          [ERROR] {error}
        </div>
      )}

      {/* Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="TOTAL SCANS"
          value={data?.totalScans?.toLocaleString()}
          subtitle={`${data?.scansToday || 0} PROCESSED TODAY`}
          icon="⌘"
          colorClass="cyber-cyan"
          glowClass="hover:glow-cyan"
        />
        <StatCard
          title="MALICIOUS DETECTED"
          value={data?.highRiskDetected?.toLocaleString()}
          subtitle="IMMEDIATE ACTION REQ"
          icon="✕"
          colorClass="cyber-red"
          glowClass="hover:glow-red"
        />
        <StatCard
          title="SUSPICIOUS DOMAINS"
          value={data?.suspiciousDomains?.toLocaleString()}
          subtitle="PENDING ANALYST REVIEW"
          icon="⚠"
          colorClass="cyber-yellow"
          glowClass="hover:glow-yellow"
        />
        <StatCard
          title="SAFE WEBSITES"
          value={data?.safeDomains?.toLocaleString()}
          subtitle={`${safePercent}% OF TRAFFIC`}
          icon="✓"
          colorClass="cyber-green"
          glowClass="hover:glow-green"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 soc-card p-6">
          <div className="mb-4">
            <h3 className="text-gray-300 font-semibold uppercase tracking-widest text-sm">Scan Activity Volume</h3>
            <p className="text-gray-500 font-mono text-[10px] mt-1">LAST 7 DAYS TREND</p>
          </div>
          <div className="h-64">
            <Line data={lineChartData} options={chartOptions} />
          </div>
        </div>
        <div className="soc-card p-6">
          <div className="mb-4">
            <h3 className="text-gray-300 font-semibold uppercase tracking-widest text-sm">Threat Distribution</h3>
            <p className="text-gray-500 font-mono text-[10px] mt-1">GLOBAL AGGREGATION</p>
          </div>
          <div className="h-64 flex justify-center items-center relative">
            {data?.totalScans > 0 ? (
              <Doughnut data={doughnutData} options={doughnutOptions} />
            ) : (
              <span className="text-gray-600 font-mono text-xs border border-gray-700 p-2 rounded">NO DATA</span>
            )}
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="soc-card overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-border bg-gray-900/50 flex justify-between items-center">
          <h3 className="text-gray-300 font-semibold uppercase tracking-widest text-sm">Recent Threat Detections</h3>
          <span className="text-cyber-cyan font-mono text-xs bg-cyber-cyan/10 px-2 py-1 rounded">LIVE FEED</span>
        </div>
        <ReportTable scans={data?.recentScans || []} />
      </div>
    </div>
  )
}
