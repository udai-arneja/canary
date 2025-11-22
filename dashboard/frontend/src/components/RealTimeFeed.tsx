import { Attack } from '../types'
import { format } from 'date-fns'

interface RealTimeFeedProps {
  attacks: Attack[]
  connectionStatus: number
}

export function RealTimeFeed({ attacks, connectionStatus }: RealTimeFeedProps) {
  const getStatusColor = () => {
    if (connectionStatus === WebSocket.OPEN) return 'bg-green-500'
    if (connectionStatus === WebSocket.CONNECTING) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  const getStatusText = () => {
    if (connectionStatus === WebSocket.OPEN) return 'Connected'
    if (connectionStatus === WebSocket.CONNECTING) return 'Connecting...'
    return 'Disconnected'
  }

  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-white">Real-Time Attack Feed</h2>
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${getStatusColor()}`}></div>
          <span className="text-sm text-slate-400">{getStatusText()}</span>
        </div>
      </div>

      <div className="space-y-3 max-h-[600px] overflow-y-auto">
        {attacks.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            No attacks detected yet. Waiting for data...
          </div>
        ) : (
          attacks.map((attack) => (
            <div
              key={attack.id}
              className={`p-4 rounded-lg border-l-4 ${
                attack.success
                  ? 'bg-red-900/20 border-red-500'
                  : 'bg-yellow-900/20 border-yellow-500'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className={`px-2 py-1 rounded text-xs font-semibold ${
                        attack.success
                          ? 'bg-red-500 text-white'
                          : 'bg-yellow-500 text-black'
                      }`}
                    >
                      {attack.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                    <span className="text-xs text-slate-400">
                      {format(new Date(attack.timestamp), 'HH:mm:ss')}
                    </span>
                  </div>
                  
                  <div className="text-sm text-white font-medium mb-1">
                    {attack.website_url}
                  </div>
                  
                  <div className="text-xs text-slate-300 space-y-1">
                    <div>
                      <span className="text-slate-500">Vulnerability:</span>{' '}
                      <span className="font-medium">{attack.vulnerability_type}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Vector:</span>{' '}
                      {attack.attack_vector}
                    </div>
                    {attack.source_ip && (
                      <div>
                        <span className="text-slate-500">Source IP:</span>{' '}
                        {attack.source_ip}
                      </div>
                    )}
                    
                    {attack.agent_indicators && (
                      <div className="mt-2 pt-2 border-t border-slate-700">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-slate-500">Agent Probability:</span>
                          <div className="flex-1 bg-slate-700 rounded-full h-2">
                            <div
                              className="bg-blue-500 h-2 rounded-full"
                              style={{
                                width: `${attack.agent_indicators.overall_agent_probability * 100}%`
                              }}
                            ></div>
                          </div>
                          <span className="text-xs">
                            {(attack.agent_indicators.overall_agent_probability * 100).toFixed(0)}%
                          </span>
                        </div>
                        {attack.agent_indicators.indicators.length > 0 && (
                          <div className="text-xs text-slate-400">
                            {attack.agent_indicators.indicators[0]}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

