<template>
  <div class="panel">
    <div class="panel-head">
      <h4>📈 异常分数 (3-sigma + IQR)</h4>
      <div class="controls">
        <el-select :model-value="stream.interval" size="small" style="width:76px" @update:model-value="stream.setIntervalRange">
          <el-option v-for="r in intervals" :key="r" :label="r" :value="r"/>
        </el-select>
        <el-select :model-value="stream.source" size="small" style="width:118px" @update:model-value="stream.setSource">
          <el-option v-for="s in sources" :key="s" :label="s" :value="s"/>
        </el-select>
        <el-button size="small" :type="stream.paused ? 'success' : 'info'" @click="stream.togglePause">
          {{ stream.paused ? '▶ 继续' : '⏸ 暂停' }}
        </el-button>
        <span class="conn" :class="stream.connState">{{ connText }}</span>
      </div>
    </div>
    <div ref="chart" class="chart"></div>
  </div>
</template>
<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { useStreamStore } from '../store/stream'

const stream = useStreamStore()
const chart = ref<HTMLDivElement>()
let inst: echarts.ECharts | null = null

const intervals = ['1m', '5m', '15m']
const sources = ['nginx', 'apache', 'json_app', 'custom']

const connText = computed(() =>
  stream.connState === 'connected' ? '● 已连接' : stream.connState === 'connecting' ? '● 连接中' : '● 已断开'
)

function render() {
  if (!inst) return
  // 曲线、得分点（异常标记）、图例全部来自同一份 stream.windows
  const ws = stream.windows
  inst.setOption({
    backgroundColor: 'transparent',
    grid: { left: 40, right: 15, top: 10, bottom: 25 },
    xAxis: { type: 'category', data: ws.map(w => 'W' + w.windowIndex), axisLabel: { color: '#94a3b8', fontSize: 9 } },
    yAxis: { type: 'value', axisLabel: { color: '#94a3b8' } },
    legend: { right: 0, textStyle: { color: '#94a3b8', fontSize: 10 } },
    series: [
      {
        type: 'line', name: '3-sigma',
        data: ws.map(w => w.sigmaScore),
        itemStyle: { color: '#f97316' }, lineStyle: { width: 1.5 }, showSymbol: false,
        markPoint: {
          symbolSize: 8, label: { show: false },
          itemStyle: { color: '#f97316' },
          data: ws.flatMap((w, i) => w.sigmaScore > 2.5 ? [{ coord: [i, w.sigmaScore] }] : [])
        }
      },
      {
        type: 'line', name: 'IQR',
        data: ws.map(w => w.iqrScore),
        itemStyle: { color: '#a78bfa' }, lineStyle: { width: 1.5 }, showSymbol: false,
        markPoint: {
          symbolSize: 8, label: { show: false },
          itemStyle: { color: '#a78bfa' },
          data: ws.flatMap((w, i) => w.iqrScore > 3.0 ? [{ coord: [i, w.iqrScore] }] : [])
        }
      }
    ],
    animation: false
  })
}

onMounted(() => {
  if (chart.value) {
    inst = echarts.init(chart.value)
    render()
    stream.connect()
    window.addEventListener('resize', resize)
  }
})

function resize() { inst?.resize() }

// 只跟随统一数据源的版本号刷新，杜绝别处状态驱动造成的错位
watch(() => stream.version, render)

onUnmounted(() => {
  window.removeEventListener('resize', resize)
  stream.dispose()
  inst?.dispose()
  inst = null
})
</script>
<style scoped>
.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}
.panel h4{color:#38bdf8;font-size:13px}
.controls{display:flex;gap:6px;align-items:center}
.conn{font-size:11px;white-space:nowrap}
.conn.connected{color:#4ade80}
.conn.connecting{color:#fbbf24}
.conn.disconnected{color:#f87171}
.chart{width:100%;height:220px}
</style>
