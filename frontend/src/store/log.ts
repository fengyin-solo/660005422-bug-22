import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import type {
  Alert,
  AlertRule,
  AnalysisResult,
  AnomalyScore,
  ConnectionStatus,
  IntervalKey,
  LogEntry,
  TimeWindow
} from '@/types'

const MAX_LOGS = 600
const DISPLAY_LOGS = 200
const SOURCE_ALL = 'all'
const LOG_TYPES = ['nginx', 'apache', 'json_app', 'custom'] as const
const INTERVAL_SIZES: Record<IntervalKey, number> = { '1m': 20, '5m': 100, '15m': 300 }

function mean(values: number[]) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0
}

function percentile(values: number[], p: number) {
  if (!values.length) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const index = (sorted.length - 1) * p
  const lower = Math.floor(index)
  const upper = Math.ceil(index)
  if (lower === upper) return sorted[lower]
  return sorted[lower] * (upper - index) + sorted[upper] * (index - lower)
}

function standardDeviation(values: number[]) {
  if (values.length < 2) return 1
  const avg = mean(values)
  return Math.sqrt(mean(values.map(value => (value - avg) ** 2))) || 1
}

export const useLogStore = defineStore('log', () => {
  const rawLogs = ref<LogEntry[]>([])
  const searchQuery = ref('')
  const logType = ref<(typeof LOG_TYPES)[number]>('nginx')
  const interval = ref<IntervalKey>('1m')
  const selectedSource = ref(SOURCE_ALL)
  const paused = ref(false)
  const connectionStatus = ref<ConnectionStatus>('connecting')

  const rules = ref<AlertRule[]>([
    { id:1, name:'高频ERROR', type:'level', threshold:5, enabled:true },
    { id:2, name:'异常流量', type:'count', threshold:200, enabled:false },
    { id:3, name:'关键词命中', type:'keyword', threshold:0, enabled:true }
  ])

  let socket: WebSocket | null = null
  let sessionId = 0
  let reconnectTimer: number | null = null
  let nextLogId = 1
  const frozenLogs = ref<LogEntry[] | null>(null)
  const bufferedLogs: LogEntry[] = []

  const activeLogs = computed(() => frozenLogs.value ?? rawLogs.value)
  const scopedLogs = computed(() => {
    const source = selectedSource.value
    return source === SOURCE_ALL
      ? activeLogs.value
      : activeLogs.value.filter(log => log.source === source)
  })

  const sourceOptions = computed(() => {
    const sources = new Set<string>()
    activeLogs.value.forEach(log => sources.add(log.source))
    return [SOURCE_ALL, ...sources]
  })

  const result = computed<AnalysisResult>(() => {
    const logs = scopedLogs.value
    const windowSize = INTERVAL_SIZES[interval.value]
    const windows: TimeWindow[] = []

    for (let start = 0; start < logs.length; start += windowSize) {
      const chunk = logs.slice(start, start + windowSize)
      const levels: Record<string, number> = {}
      const sources: Record<string, number> = {}
      chunk.forEach(log => {
        levels[log.level] = (levels[log.level] || 0) + 1
        sources[log.source] = (sources[log.source] || 0) + 1
      })
      windows.push({ start, end: start + chunk.length, count: chunk.length, levels, sources })
    }

    const counts = windows.map(window => window.count)
    const avg = mean(counts)
    const std = standardDeviation(counts)
    const q1 = counts.length > 3 ? percentile(counts, 0.25) : avg - std
    const q3 = counts.length > 3 ? percentile(counts, 0.75) : avg + std
    const iqr = q3 - q1 || 1
    const anomalies: AnomalyScore[] = windows.map((window, index) => {
      const sigmaScore = Math.abs(window.count - avg) / Math.max(std, 1e-5)
      const iqrLow = q1 - 1.5 * iqr
      const iqrHigh = q3 + 1.5 * iqr
      const outsideIqr = window.count < iqrLow || window.count > iqrHigh
      const iqrScore = outsideIqr ? Math.min(10, Math.abs(window.count - avg) / Math.max(iqr, 1e-5)) : 0
      return {
        windowIndex: index,
        sigmaScore: Number(sigmaScore.toFixed(2)),
        iqrScore: Number(iqrScore.toFixed(2)),
        isAnomaly: sigmaScore > 2.5 || iqrScore > 3,
        timestamp: logs[index * windowSize]?.timestamp || ''
      }
    })

    const query = searchQuery.value.trim().toLowerCase()
    const queryTerms = query ? query.split(/\s+/) : []
    const displayLogs = query
      ? logs
          .map(log => ({ log, score: queryTerms.reduce((sum, term) => sum + (log.raw.toLowerCase().includes(term) ? 1 : 0), 0) }))
          .filter(item => item.score > 0)
          .sort((a, b) => b.score - a.score)
          .slice(0, DISPLAY_LOGS)
          .map(item => item.log)
      : logs.slice(0, DISPLAY_LOGS)

    const alerts: Alert[] = []
    rules.value.filter(rule => rule.enabled).forEach(rule => {
      windows.forEach(window => {
        if (rule.type === 'level' && (window.levels.ERROR || 0) > rule.threshold) {
          alerts.push({
            id: alerts.length + 1,
            ruleName: rule.name,
            severity: 'high',
            message: `窗口${window.start}内ERROR日志${window.levels.ERROR || 0}条超过阈值${rule.threshold}`,
            timestamp: logs[window.start]?.timestamp || ''
          })
        }
        if (rule.type === 'count' && window.count > rule.threshold) {
          alerts.push({
            id: alerts.length + 1,
            ruleName: rule.name,
            severity: 'medium',
            message: `窗口${window.start}日志量${window.count}超过阈值`,
            timestamp: logs[window.start]?.timestamp || ''
          })
        }
      })
    })
    anomalies.forEach(anomaly => {
      if (anomaly.isAnomaly) {
        alerts.push({
          id: alerts.length + 1,
          ruleName: '统计异常检测',
          severity: anomaly.sigmaScore > 4 ? 'critical' : 'high',
          message: `窗口${anomaly.windowIndex}: 3-sigma=${anomaly.sigmaScore}, IQR=${anomaly.iqrScore}`,
          timestamp: anomaly.timestamp
        })
      }
    })

    return {
      logs: displayLogs,
      windows,
      anomalies,
      alerts: alerts.slice(0, 20),
      totalLogs: logs.length
    }
  })

  function appendLog(entry: Omit<LogEntry, 'id'>) {
    const log = { ...entry, id: nextLogId++ }
    if (paused.value) {
      bufferedLogs.push(log)
      if (bufferedLogs.length > MAX_LOGS) bufferedLogs.splice(0, bufferedLogs.length - MAX_LOGS)
      return
    }
    rawLogs.value = [...rawLogs.value.slice(-(MAX_LOGS - 1)), log]
  }

  function clearReconnectTimer() {
    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function closeSocket() {
    if (!socket) return
    socket.onopen = null
    socket.onmessage = null
    socket.onerror = null
    socket.onclose = null
    socket.close()
    socket = null
  }

  function connect() {
    const currentSession = ++sessionId
    clearReconnectTimer()
    closeSocket()
    connectionStatus.value = 'connecting'

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    socket = new WebSocket(`${protocol}//${window.location.host}/ws/stream?type=${encodeURIComponent(logType.value)}`)

    socket.onopen = () => {
      if (currentSession !== sessionId) return
      connectionStatus.value = 'connected'
    }
    socket.onmessage = event => {
      if (currentSession !== sessionId) return
      try {
        const data = JSON.parse(event.data as string) as Omit<LogEntry, 'id'>
        if (data?.timestamp && data?.level && data?.source && data?.message) appendLog(data)
      } catch {
        // Ignore malformed stream frames without dropping the connection.
      }
    }
    socket.onerror = () => socket?.close()
    socket.onclose = () => {
      if (currentSession !== sessionId) return
      socket = null
      connectionStatus.value = 'disconnected'
      clearReconnectTimer()
      reconnectTimer = window.setTimeout(connect, 2000)
    }
  }

  function togglePause() {
    if (paused.value) {
      if (bufferedLogs.length) {
        rawLogs.value = [...rawLogs.value, ...bufferedLogs].slice(-MAX_LOGS)
        bufferedLogs.length = 0
      }
      frozenLogs.value = null
      paused.value = false
    } else {
      frozenLogs.value = rawLogs.value
      paused.value = true
    }
  }

  function resetStream() {
    rawLogs.value = []
    frozenLogs.value = null
    bufferedLogs.length = 0
    nextLogId = 1
    paused.value = false
    connect()
  }

  watch(logType, () => {
    selectedSource.value = SOURCE_ALL
    resetStream()
  })
  watch(sourceOptions, options => {
    if (selectedSource.value !== SOURCE_ALL && !options.includes(selectedSource.value)) {
      selectedSource.value = SOURCE_ALL
    }
  })

  return {
    result,
    searchQuery,
    logType,
    interval,
    selectedSource,
    sourceOptions,
    paused,
    connectionStatus,
    rules,
    connect,
    togglePause
  }
})
