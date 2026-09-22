<template>
  <div class="app-root">
    <header class="top-bar">
      <h1>📊 分布式日志聚合与智能异常检测平台</h1>
      <div class="toolbar">
        <el-select v-model="store.logType" size="small" style="width:120px">
          <el-option v-for="t in ['nginx','apache','json_app','custom']" :key="t" :label="t" :value="t"/>
        </el-select>
        <el-select v-model="store.interval" size="small" style="width:90px">
          <el-option label="1分钟" value="1m"/>
          <el-option label="5分钟" value="5m"/>
          <el-option label="15分钟" value="15m"/>
        </el-select>
        <el-select v-model="store.selectedSource" size="small" style="width:130px">
          <el-option label="全部来源" value="all"/>
          <el-option v-for="s in store.sourceOptions.filter(s => s !== 'all')" :key="s" :label="s" :value="s"/>
        </el-select>
        <el-input v-model="store.searchQuery" placeholder="搜索关键词..." size="small" style="width:180px" clearable/>
        <el-button size="small" @click="store.togglePause()">
          {{ store.paused ? '▶ 继续' : '⏸ 暂停' }}
        </el-button>
        <span class="conn-status" :class="store.connectionStatus">{{ statusText }}</span>
      </div>
    </header>
    <div class="main-grid">
      <div class="grid-col">
        <LogTable />
      </div>
      <div class="grid-col">
        <AnomalyChart />
        <AlertPanel />
      </div>
    </div>
    <div class="bottom-row">
      <TrendChart />
      <HeatmapChart />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import LogTable from './components/LogTable.vue'
import AnomalyChart from './components/AnomalyChart.vue'
import AlertPanel from './components/AlertPanel.vue'
import TrendChart from './components/TrendChart.vue'
import HeatmapChart from './components/HeatmapChart.vue'
import { useLogStore } from './store/log'
const store = useLogStore()
const statusText = computed(() => {
  if (store.connectionStatus === 'connected') return '已连接'
  if (store.connectionStatus === 'connecting') return '连接中'
  return '重连中'
})

onMounted(() => store.connect())
</script>

<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,monospace;background:#0f172a;color:#e2e8f0}
.app-root{min-height:100vh}
.top-bar{display:flex;justify-content:space-between;align-items:center;padding:10px 20px;background:#1e293b;border-bottom:1px solid #334155}
.top-bar h1{font-size:1.1rem;color:#38bdf8}
.toolbar{display:flex;gap:8px;align-items:center}
.conn-status{display:inline-flex;align-items:center;gap:4px;font-size:11px;color:#94a3b8;white-space:nowrap}
.conn-status::before{content:'';width:7px;height:7px;border-radius:50%;background:#64748b}
.conn-status.connected::before{background:#22c55e;box-shadow:0 0 6px #22c55e}
.conn-status.connecting::before{background:#fbbf24}
.conn-status.disconnected::before{background:#ef4444}
.main-grid{display:grid;grid-template-columns:1fr 400px;gap:12px;padding:12px 20px;min-height:50vh}
.grid-col{overflow:hidden}
.bottom-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 20px 16px}
</style>