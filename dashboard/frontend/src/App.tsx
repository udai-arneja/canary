import { useState, useEffect } from 'react'
import { RealTimeFeed } from './components/RealTimeFeed'
import { StatsOverview } from './components/StatsOverview'
import { RiskForecast } from './components/RiskForecast'
import { useWebSocket } from './hooks/useWebSocket'
import { Attack } from './types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [stats, setStats] = useState<any>(null)
  const [forecast, setForecast] = useState<any>(null)
  const wsUrl = API_BASE.replace(/^http/, 'ws')
  const { lastMessage, readyState } = useWebSocket(`${wsUrl}/ws`)

  // Handle new attack from WebSocket
  useEffect(() => {
    if (lastMessage?.type === 'new_attack') {
      setAttacks(prev => [lastMessage.data, ...prev].slice(0, 100)) // Keep last 100
    }
  }, [lastMessage])

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attacksRes, statsRes, forecastRes] = await Promise.all([
          fetch(`${API_BASE}/api/attacks?limit=50`),
          fetch(`${API_BASE}/api/stats`),
          fetch(`${API_BASE}/api/risk-forecast`)
        ])
        
        const attacksData = await attacksRes.json()
        const statsData = await statsRes.json()
        const forecastData = await forecastRes.json()
        
        setAttacks(attacksData)
        setStats(statsData)
        setForecast(forecastData)
      } catch (error) {
        console.error('Error fetching data:', error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-white">
            AI Cyber Attack Monitoring Dashboard
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time threat detection and risk forecasting
          </p>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-2">
            <RealTimeFeed attacks={attacks} connectionStatus={readyState} />
          </div>
          <div>
            {forecast && <RiskForecast forecast={forecast} />}
          </div>
        </div>

        {stats && <StatsOverview stats={stats} />}
      </main>
    </div>
  )
}

export default App

