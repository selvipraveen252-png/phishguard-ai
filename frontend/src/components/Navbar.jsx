import { Link, useLocation } from 'react-router-dom'

const navLinks = [
  { path: '/', label: 'Overview', icon: '◱' },
  { path: '/scan', label: 'URL Scanner', icon: '⌕' },
  { path: '/domain', label: 'Domain Intel', icon: '⌘' },
]

export default function Navbar() {
  const location = useLocation()

  return (
    <aside className="fixed left-0 top-0 h-full w-64 bg-cyber-card border-r border-cyber-border z-50 flex flex-col">
      {/* Brand */}
      <div className="h-20 flex items-center px-6 border-b border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-cyber-bg border border-cyber-cyan/30 flex items-center justify-center glow-cyan shadow-none relative overflow-hidden">
            <div className="absolute inset-0 bg-cyber-cyan/20 animate-pulse-slow"></div>
            <span className="text-cyber-cyan font-mono font-bold text-sm relative z-10">PG</span>
          </div>
          <div>
            <h1 className="text-white font-bold tracking-wide text-lg leading-tight uppercase relative">
              PhishGuard
              <span className="absolute -top-1 -right-4 w-2 h-2 rounded-full bg-cyber-cyan animate-pulse"></span>
            </h1>
            <span className="text-gray-500 text-[10px] font-mono tracking-widest uppercase">Threat Intel System</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-8 px-4 space-y-2">
        <p className="px-3 text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">Core Modules</p>
        {navLinks.map(link => {
          const isActive = location.pathname === link.path
          return (
            <Link
              key={link.path}
              to={link.path}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative overflow-hidden ${
                isActive 
                  ? 'text-white bg-cyber-bg border border-cyber-border' 
                  : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
              }`}
            >
              {isActive && (
                <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-cyan"></div>
              )}
              <span className={`text-lg font-mono ${isActive ? 'text-cyber-cyan' : 'text-gray-500 group-hover:text-gray-300'}`}>
                {link.icon}
              </span>
              <span>{link.label}</span>
            </Link>
          )
        })}
      </nav>

      {/* System Status */}
      <div className="p-6 border-t border-cyber-border bg-gray-900/30">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-gray-400">SOC STATUS</span>
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-green opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-green"></span>
          </span>
        </div>
        <div className="space-y-1">
          <div className="flex justify-between text-[11px] font-mono">
            <span className="text-gray-500">API Gateway</span>
            <span className="text-cyber-green">ONLINE</span>
          </div>
          <div className="flex justify-between text-[11px] font-mono">
            <span className="text-gray-500">Intel Engines</span>
            <span className="text-cyber-green">ACTIVE</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
