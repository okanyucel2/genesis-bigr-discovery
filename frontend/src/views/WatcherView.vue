<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  RefreshCw,
  Loader2,
  AlertTriangle,
  Eye,
  EyeOff,
  Play,
  Clock,
  Radio,
  Activity,
  Zap,
} from 'lucide-vue-next'
import { useWatcher } from '@/composables/useWatcher'

const {
  status,
  history,
  alerts,
  loading,
  error,
  isRunning,
  triggerScan,
  refreshAll,
} = useWatcher()

const activeTab = ref<'history' | 'alerts'>('history')
const scanning = ref(false)

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}sn`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}dk`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}sa ${m}dk`
}

function formatDate(iso: string | null): string {
  if (!iso) return '-'
  return iso.substring(0, 16).replace('T', ' ')
}

function severityColor(severity: string): string {
  if (severity === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20'
  if (severity === 'warning') return 'bg-amber-500/10 text-amber-400 border-amber-500/20'
  return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
}

function severityLabel(severity: string): string {
  if (severity === 'critical') return 'Kritik'
  if (severity === 'warning') return 'Uyari'
  return 'Bilgi'
}

async function handleScanNow() {
  scanning.value = true
  await triggerScan()
  scanning.value = false
}

onMounted(() => {
  refreshAll()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Surekli Izleme</h1>
        <p class="mt-1 text-sm text-slate-400">
          Ag taramalarini otomatik planla, degisiklikleri izle, alertleri takip et.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <button
          class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-3 py-2 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          :disabled="scanning"
          @click="handleScanNow"
        >
          <Play v-if="!scanning" class="h-3.5 w-3.5" />
          <Loader2 v-else class="h-3.5 w-3.5 animate-spin" />
          Hemen Tara
        </button>
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="refreshAll"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Yenile
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !status"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Izleme durumu yukleniyor...</p>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Status Banner -->
      <div
        class="glass-card rounded-xl border p-5"
        :class="isRunning ? 'border-emerald-500/20' : 'border-amber-500/20 bg-amber-500/5'"
      >
        <div class="flex items-center gap-4">
          <div
            class="flex h-12 w-12 items-center justify-center rounded-xl"
            :class="isRunning ? 'bg-emerald-500/10' : 'bg-amber-500/10'"
          >
            <Eye v-if="isRunning" class="h-6 w-6 text-emerald-400" />
            <EyeOff v-else class="h-6 w-6 text-amber-400" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-lg font-semibold text-white">
                {{ isRunning ? 'Izleme Aktif' : 'Izleme Durdurulmus' }}
              </h2>
              <span
                v-if="isRunning"
                class="relative flex h-2.5 w-2.5"
              >
                <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span class="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
              </span>
            </div>
            <p class="text-xs text-slate-400">
              <template v-if="isRunning">
                PID: {{ status?.pid }} |
                {{ status?.targets?.length || 0 }} hedef izleniyor
              </template>
              <template v-else>
                Watcher daemon calismıyor. CLI ile baslatin: <code class="text-cyan-400">bigr watch</code>
              </template>
            </p>
          </div>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-white">
            {{ isRunning ? formatUptime(status?.uptime_seconds || 0) : '-' }}
          </div>
          <div class="mt-1 text-xs text-slate-400">Calisma Suresi</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-cyan-500/20">
          <div class="text-3xl font-bold text-cyan-400">
            {{ status?.scan_count || 0 }}
          </div>
          <div class="mt-1 text-xs text-slate-400">Toplam Tarama</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-white">
            {{ status?.last_scan_at ? formatDate(status.last_scan_at) : '-' }}
          </div>
          <div class="mt-1 text-xs text-slate-400">Son Tarama</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-amber-500/20">
          <div class="text-3xl font-bold text-amber-400">
            {{ alerts.length }}
          </div>
          <div class="mt-1 text-xs text-slate-400">Aktif Alert</div>
        </div>
      </div>

      <!-- Targets -->
      <div v-if="status?.targets?.length" class="glass-card rounded-xl border border-white/5 p-5">
        <h3 class="text-sm font-semibold text-white mb-3">Izlenen Hedefler</h3>
        <div class="flex flex-wrap gap-2">
          <div
            v-for="target in status.targets"
            :key="target.subnet"
            class="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5"
          >
            <Radio class="h-3.5 w-3.5 text-cyan-400" />
            <span class="font-mono text-sm text-white">{{ target.subnet }}</span>
            <span class="text-[10px] text-slate-500">/ {{ Math.floor(target.interval_seconds / 60) }}dk</span>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex gap-1 rounded-lg bg-white/5 p-1">
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'history' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'history'"
        >
          <Clock class="h-4 w-4" />
          Tarama Gecmisi ({{ history.length }})
        </button>
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'alerts' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'alerts'"
        >
          <Activity class="h-4 w-4" />
          Alertler ({{ alerts.length }})
        </button>
      </div>

      <!-- History Tab -->
      <div v-if="activeTab === 'history'" class="space-y-4">
        <div
          v-if="history.length === 0"
          class="glass-card rounded-xl p-12 text-center"
        >
          <Clock class="mx-auto h-12 w-12 text-slate-600" />
          <h2 class="mt-4 text-lg font-semibold text-white">Henuz tarama yapilmamis</h2>
          <p class="mt-2 text-sm text-slate-400">
            Watcher baslayinca tarama gecmisi burada gorunecek.
          </p>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Subnet</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Baslangic</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Cihaz</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Degisiklik</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Durum</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="(scan, i) in history"
                :key="i"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3 font-mono text-sm text-white">{{ scan.subnet }}</td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ formatDate(scan.started_at) }}</td>
                <td class="px-4 py-3 font-mono text-sm text-slate-300">{{ scan.asset_count }}</td>
                <td class="px-4 py-3">
                  <span
                    v-if="scan.changes_count > 0"
                    class="inline-flex items-center gap-1 rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400"
                  >
                    <Zap class="h-2.5 w-2.5" />
                    {{ scan.changes_count }}
                  </span>
                  <span v-else class="text-xs text-slate-500">-</span>
                </td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center gap-1 text-xs font-medium"
                    :class="scan.status === 'completed' ? 'text-emerald-400' : 'text-red-400'"
                  >
                    <span
                      class="h-1.5 w-1.5 rounded-full"
                      :class="scan.status === 'completed' ? 'bg-emerald-400' : 'bg-red-400'"
                    />
                    {{ scan.status === 'completed' ? 'Tamam' : 'Hata' }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Alerts Tab -->
      <div v-if="activeTab === 'alerts'" class="space-y-4">
        <div
          v-if="alerts.length === 0"
          class="glass-card rounded-xl p-12 text-center"
        >
          <Activity class="mx-auto h-12 w-12 text-slate-600" />
          <h2 class="mt-4 text-lg font-semibold text-white">Alert yok</h2>
          <p class="mt-2 text-sm text-slate-400">
            Ag degisiklikleri tespit edildiginde alertler burada gorunecek.
          </p>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Zaman</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Seviye</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Tip</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">IP</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Mesaj</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="(alert, i) in alerts"
                :key="i"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3 text-xs text-slate-400">{{ formatDate(alert.timestamp) }}</td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex rounded-md border px-2 py-0.5 text-[10px] font-medium"
                    :class="severityColor(alert.severity)"
                  >
                    {{ severityLabel(alert.severity) }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <span class="inline-flex rounded-md border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-medium text-slate-400">
                    {{ alert.alert_type }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-sm text-white">{{ alert.ip }}</td>
                <td class="px-4 py-3 text-xs text-slate-300">{{ alert.message }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Error Display -->
      <div
        v-if="error"
        class="glass-card rounded-xl border border-red-500/20 bg-red-500/5 p-4"
      >
        <div class="flex items-center gap-2">
          <AlertTriangle class="h-4 w-4 text-red-400" />
          <span class="text-sm text-red-400">{{ error }}</span>
        </div>
      </div>
    </template>
  </div>
</template>
