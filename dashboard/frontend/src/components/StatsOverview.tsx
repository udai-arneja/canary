import { Stats } from '../types'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { format } from 'date-fns'

interface StatsOverviewProps {
  stats: Stats
}

const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

export function StatsOverview({ stats }: StatsOverviewProps) {
  const timeSeriesData = stats.time_series.map(item => ({
    time: format(new Date(item.timestamp), 'HH:mm'),
    attacks: item.count
  }))

  const vulnerabilityData = stats.vulnerability_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(v => ({
      name: v.type.length > 20 ? v.type.substring(0, 20) + '...' : v.type,
      total: v.total,
      successful: v.successful,
      failed: v.total - v.successful
    }))

  const websiteData = stats.website_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(w => ({
      name: w.url.length > 30 ? w.url.substring(0, 30) + '...' : w.url,
      total: w.total,
      successful: w.successful
    }))

  const attackVectorData = stats.attack_vectors.map(v => ({
    name: v.vector,
    value: v.count
  }))

  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Total Attacks"
          value={stats.total_attacks.toLocaleString()}
          subtitle="All time"
          color="text-blue-400"
        />
        <MetricCard
          title="24h Attacks"
          value={stats.attacks_24h.toLocaleString()}
          subtitle="Last 24 hours"
          color="text-yellow-400"
        />
        <MetricCard
          title="Successful"
          value={stats.successful_attacks.toLocaleString()}
          subtitle={`${stats.total_attacks > 0 ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1) : 0}% success rate`}
          color="text-red-400"
        />
        <MetricCard
          title="Websites Targeted"
          value={stats.websites_attacked.toLocaleString()}
          subtitle="Unique targets"
          color="text-green-400"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Timeline */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Attack Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="attacks"
                stroke="#ef4444"
                strokeWidth={2}
                name="Attacks"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Vectors */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Attack Vectors</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={attackVectorData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {attackVectorData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top Vulnerabilities */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Top Vulnerabilities</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={vulnerabilityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="name" stroke="#94a3b8" angle={-45} textAnchor="end" height={100} />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Bar dataKey="successful" stackId="a" fill="#ef4444" name="Successful" />
              <Bar dataKey="failed" stackId="a" fill="#f59e0b" name="Failed" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top Websites */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Most Targeted Websites</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={websiteData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="name" stroke="#94a3b8" angle={-45} textAnchor="end" height={100} />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Bar dataKey="total" fill="#3b82f6" name="Total Attacks" />
              <Bar dataKey="successful" fill="#ef4444" name="Successful" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Vulnerability Lists */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Successfully Exploited</h3>
          <div className="space-y-2">
            {stats.successful_vulnerabilities.length === 0 ? (
              <p className="text-slate-400">None</p>
            ) : (
              stats.successful_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-red-900/20 rounded text-sm text-red-300">
                  {vuln}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Failed Exploitation Attempts</h3>
          <div className="space-y-2">
            {stats.failed_vulnerabilities.length === 0 ? (
              <p className="text-slate-400">None</p>
            ) : (
              stats.failed_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-yellow-900/20 rounded text-sm text-yellow-300">
                  {vuln}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, subtitle, color }: {
  title: string
  value: string
  subtitle: string
  color: string
}) {
  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6">
      <div className="text-sm text-slate-400 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color} mb-1`}>{value}</div>
      <div className="text-xs text-slate-500">{subtitle}</div>
    </div>
  )
}

