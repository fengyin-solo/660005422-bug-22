import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { ScoreWindow, StreamConnState } from '@/types'

const STREAM_WINDOW_LIMIT = 120
const MAX_RETRY_DELAY = 10000

export const useStreamStore = defineStore('stream', () => {
  // 唯一的一份窗口数据：曲线、得分点、图例全部从这份数据派生
  const windows = ref<ScoreWindow[]>([])
  // 唯一的一份连接状态：徽标、暂停按钮、重连调度都以它为准
  const connState = ref<StreamConnState>('disconnected')
  const interval = ref('1m')
  const source = ref('nginx')
  const paused = ref(false)

  let socket: WebSocket | null = null
  let retryTimer: ReturnType<typeof setTimeout> | null = null
  let retryDelay = 1000
  // 会话代次：切换区间/来源时递增，旧连接的回调全部作废，防止上一段数据混入
  let session = 0
  let disposed = false

  // 暂停期间到达的窗口先缓冲，继续时并入同一份 windows
  const pending: ScoreWindow[] = []
  const version = ref(0)

  function ingestWindow(w: ScoreWindow) {
    if (paused.value) {
      pending.push(w)
      return
    }
    windows.value.push(w)
    if (windows.value.length > STREAM_WINDOW_LIMIT) {
      windows.value = windows.value.slice(-STREAM_WINDOW_LIMIT)
    }
    version.value++
  }

  function clearRetry() {
    if (retryTimer !== null) {
      clearTimeout(retryTimer)
      retryTimer = null
    }
  }

  function closeSocket() {
    if (socket) {
      socket.onopen = null
      socket.onmessage = null
      socket.onclose = null
      socket.onerror = null
      try { socket.close() } catch { /* ignore */ }
      socket = null
    }
  }

  function connect(restart = false) {
    if (restart) {
      session++
      retryDelay = 1000
    }
    clearRetry()
    closeSocket()

    const mySession = session
    windows.value = []
    pending.length = 0
    version.value++
    connState.value = 'connecting'

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${location.host}/ws/stream?source=${encodeURIComponent(source.value)}&interval=${encodeURIComponent(interval.value)}`
    const ws = new WebSocket(url)
    socket = ws

    ws.onopen = () => {
      if (mySession !== session) return
      connState.value = 'connected'
      retryDelay = 1000
    }

    ws.onmessage = (ev) => {
      if (mySession !== session) return
      let msg: { type?: string; windows?: ScoreWindow[]; window?: ScoreWindow }
      try { msg = JSON.parse(ev.data as string) } catch { return }
      if (msg.type === 'snapshot' && Array.isArray(msg.windows)) {
        // 重连/切换后的快照整体替换，页面上不会残留上一段取值
        windows.value = msg.windows.slice()
        version.value++
      } else if (msg.type === 'window' && msg.window) {
        ingestWindow(msg.window)
      }
    }

    ws.onerror = () => {
      if (mySession !== session) return
      connState.value = 'disconnected'
    }

    ws.onclose = () => {
      if (mySession !== session) return
      connState.value = 'disconnected'
      socket = null
      scheduleRetry(mySession)
    }
  }

  function scheduleRetry(mySession: number) {
    if (disposed || mySession !== session) return
    clearRetry()
    retryTimer = setTimeout(() => {
      if (disposed || mySession !== session) return
      connect()
    }, retryDelay)
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY)
  }

  function setIntervalRange(v: string) {
    if (v === interval.value) return
    interval.value = v
    paused.value = false
    // 连续切换区间：每次都以新会话重连并立刻清空旧数据
    connect(true)
  }

  function setSource(v: string) {
    if (v === source.value) return
    source.value = v
    paused.value = false
    connect(true)
  }

  function togglePause() {
    if (paused.value) {
      paused.value = false
      // 继续：缓冲窗口按序并入同一份数据，得分点不会跳回开头
      if (pending.length) {
        windows.value = windows.value.concat(pending.splice(0))
        if (windows.value.length > STREAM_WINDOW_LIMIT) {
          windows.value = windows.value.slice(-STREAM_WINDOW_LIMIT)
        }
        version.value++
      }
    } else {
      paused.value = true
    }
  }

  function dispose() {
    disposed = true
    session++
    clearRetry()
    closeSocket()
    windows.value = []
    pending.length = 0
    connState.value = 'disconnected'
  }

  return {
    windows, version, connState, interval, source, paused,
    connect, setIntervalRange, setSource, togglePause, dispose,
  }
})
