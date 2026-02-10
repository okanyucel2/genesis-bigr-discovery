<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useCollective } from '@/composables/useCollective'

const {
  stats,
  feed,
  contribution,
  loading,
  error,
  fetchAll,
} = useCollective()

onMounted(() => {
  fetchAll()
})

const protectionColor = computed(() => {
  const score = stats.value?.community_protection_score ?? 0
  if (score >= 80) return '#10b981' // emerald
  if (score >= 50) return '#06b6d4' // cyan
  if (score >= 30) return '#eab308' // yellow
  return '#ef4444' // red
})

const signalTypeLabels: Record<string, string> = {
  port_scan: 'Port Taramasi',
  malware_c2: 'Zararli Yazilim C2',
  brute_force: 'Kaba Kuvvet',
  suspicious: 'Suppheli Aktivite',
}

const signalTypeColors: Record<string, string> = {
  port_scan: '#f59e0b',
  malware_c2: '#ef4444',
  brute_force: '#f97316',
  suspicious: '#8b5cf6',
}

function severityBadgeColor(severity: number): string {
  if (severity >= 0.8) return '#ef4444'
  if (severity >= 0.6) return '#f97316'
  if (severity >= 0.4) return '#eab308'
  return '#10b981'
}

function formatTime(iso: string): string {
  if (!iso) return '-'
  return iso.substring(0, 19).replace('T', ' ')
}

function truncateHash(hash: string): string {
  if (!hash) return '-'
  return hash.substring(0, 12) + '...'
}

function getSignalLabel(type: string): string {
  return signalTypeLabels[type] || type
}

function getSignalColor(type: string): string {
  return signalTypeColors[type] || '#6b7280'
}
</script>

<template>
  <div class="space-y-6">
    <!-- Page Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Topluluk Korumasi</h1>
        <p class="mt-1 text-sm text-slate-400">
          Kolektif istihbarat agi &mdash; Her kullanici herkesi daha guvenli yapar
        </p>
      </div>
      <button
        class="rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition hover:bg-cyan-500/30"
        @click="fetchAll"
        :disabled="loading"
      >
        {{ loading ? 'Yukleniyor...' : 'Yenile' }}
      </button>
    </div>

    <!-- Error -->
    <div
      v-if="error"
      class="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400"
    >
      {{ error }}
    </div>

    <!-- Community Protection Score (Big Gauge) -->
    <div class="glass-panel rounded-xl border border-[var(--border-glass)] p-8 text-center">
      <div class="relative mx-auto mb-4 flex h-40 w-40 items-center justify-center">
        <!-- Pulse ring animation -->
        <div
          class="absolute inset-0 animate-ping rounded-full opacity-20"
          :style="{ backgroundColor: protectionColor }"
        />
        <div
          class="absolute inset-2 rounded-full opacity-10"
          :style="{ backgroundColor: protectionColor }"
        />
        <div class="relative z-10 text-center">
          <div
            class="text-5xl font-extrabold"
            :style="{ color: protectionColor }"
          >
            {{ stats?.community_protection_score?.toFixed(0) ?? '-' }}
          </div>
          <div class="mt-1 text-xs uppercase tracking-widest text-slate-500">Puan</div>
        </div>
      </div>
      <h2 class="text-lg font-semibold text-white">Topluluk Koruma Skoru</h2>
      <p class="mt-1 text-sm text-slate-400">
        Tum BIGR kullanicilari tarafindan olusturulan kolektif guvenlik seviyesi
      </p>
    </div>

    <!-- Stats Row -->
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-5 text-center">
        <div class="text-3xl font-bold text-white">
          {{ stats?.active_agents ?? '-' }}
        </div>
        <div class="mt-1 text-xs text-slate-400">Aktif Ajan</div>
        <div class="mt-0.5 text-[10px] text-slate-500">Son 24 saat</div>
      </div>
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-5 text-center">
        <div class="text-3xl font-bold text-emerald-400">
          {{ stats?.verified_threats ?? '-' }}
        </div>
        <div class="mt-1 text-xs text-slate-400">Dogrulanmis Tehdit</div>
        <div class="mt-0.5 text-[10px] text-slate-500">k-anonymity saglandi</div>
      </div>
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-5 text-center">
        <div class="text-3xl font-bold text-cyan-400">
          {{ stats?.subnets_monitored ?? '-' }}
        </div>
        <div class="mt-1 text-xs text-slate-400">Izlenen Alt Ag</div>
        <div class="mt-0.5 text-[10px] text-slate-500">Son 72 saat</div>
      </div>
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-5 text-center">
        <div class="text-3xl font-bold text-amber-400">
          {{ stats?.total_signals ?? '-' }}
        </div>
        <div class="mt-1 text-xs text-slate-400">Toplam Sinyal</div>
        <div class="mt-0.5 text-[10px] text-slate-500">Anonim raporlar</div>
      </div>
    </div>

    <!-- Two Columns: Contribution + Privacy -->
    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <!-- Contribution Panel -->
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">
          Senin Katkin
        </h3>
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-sm text-slate-400">Gonderilen Sinyaller</span>
            <span class="text-lg font-bold text-white">
              {{ contribution?.signals_contributed ?? 0 }}
            </span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm text-slate-400">Alinan Tehdit Uyarilari</span>
            <span class="text-lg font-bold text-cyan-400">
              {{ contribution?.signals_received ?? 0 }}
            </span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm text-slate-400">Katilim Durumu</span>
            <span
              class="rounded-full px-3 py-0.5 text-xs font-medium"
              :class="
                contribution?.is_contributing
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : 'bg-slate-500/20 text-slate-400'
              "
            >
              {{ contribution?.is_contributing ? 'Aktif' : 'Pasif' }}
            </span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm text-slate-400">Gizlilik Seviyesi</span>
            <span class="text-sm font-medium text-purple-400">
              {{ contribution?.privacy_level ?? 'standard' }}
            </span>
          </div>
        </div>

        <!-- Opt-in Toggle Visual -->
        <div class="mt-6 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
          <div class="flex items-center gap-3">
            <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/20">
              <svg class="h-5 w-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">Sen de katki sagla!</p>
              <p class="text-xs text-slate-400">
                Anonim tehdit sinyalleri ile toplulugu koru
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Privacy Info Panel -->
      <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">
          Gizlilik Garantisi
        </h3>
        <div class="space-y-4">
          <div class="flex items-start gap-3">
            <div class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-emerald-500/20">
              <svg class="h-3.5 w-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">HMAC-SHA256 Sifreleme</p>
              <p class="text-xs text-slate-400">IP adresleri geri donusumsuz olarak hashlenir</p>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <div class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-emerald-500/20">
              <svg class="h-3.5 w-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">Diferansiyel Gizlilik</p>
              <p class="text-xs text-slate-400">Laplace gurultusu ile bireysel veriler korunur (epsilon={{ stats ? '1.0' : '-' }})</p>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <div class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-emerald-500/20">
              <svg class="h-3.5 w-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">k-Anonimlik</p>
              <p class="text-xs text-slate-400">Sinyal en az 3 farkli kullanici raporladiginda paylasilir</p>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <div class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-emerald-500/20">
              <svg class="h-3.5 w-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">/24 Alt Ag Toplulastirma</p>
              <p class="text-xs text-slate-400">Bireysel IP adresleri asla paylasılmaz</p>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <div class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-emerald-500/20">
              <svg class="h-3.5 w-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p class="text-sm font-medium text-white">GDPR/KVKK Uyumlu</p>
              <p class="text-xs text-slate-400">Verileriniz anonim ve sifrelenimistir</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Collective Threat Feed -->
    <div class="glass-panel rounded-lg border border-[var(--border-glass)] p-6">
      <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">
        Topluluk Tehdit Akisi
      </h3>

      <div v-if="loading" class="py-8 text-center text-sm text-slate-500">
        Yukleniyor...
      </div>

      <div
        v-else-if="!feed?.signals?.length"
        class="py-8 text-center text-sm text-slate-500"
      >
        Henuz dogrulanmis topluluk sinyali yok.
      </div>

      <div v-else class="overflow-x-auto">
        <table class="w-full text-left">
          <thead>
            <tr class="border-b border-slate-700/50">
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Tur</th>
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Alt Ag</th>
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Siddet</th>
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Raporlayanlar</th>
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Guven</th>
              <th class="pb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Son Gorulme</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(signal, idx) in feed.signals"
              :key="idx"
              class="border-b border-slate-800/50 transition hover:bg-white/[0.02]"
            >
              <td class="py-3 pr-4">
                <span
                  class="inline-block rounded px-2 py-0.5 text-xs font-medium text-white"
                  :style="{ backgroundColor: getSignalColor(signal.signal_type) }"
                >
                  {{ getSignalLabel(signal.signal_type) }}
                </span>
              </td>
              <td class="py-3 pr-4 font-mono text-xs text-cyan-300">
                {{ truncateHash(signal.subnet_hash) }}
              </td>
              <td class="py-3 pr-4">
                <span
                  class="inline-block rounded px-2 py-0.5 text-xs font-bold"
                  :style="{ color: severityBadgeColor(signal.avg_severity) }"
                >
                  {{ signal.avg_severity.toFixed(2) }}
                </span>
              </td>
              <td class="py-3 pr-4 text-sm text-white">
                {{ signal.reporter_count }}
              </td>
              <td class="py-3 pr-4 text-sm text-slate-300">
                {{ (signal.confidence * 100).toFixed(0) }}%
              </td>
              <td class="py-3 text-xs text-slate-500">
                {{ formatTime(signal.last_seen) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Last Updated -->
    <div class="text-center text-xs text-slate-600">
      Son guncelleme: {{ stats?.last_updated ? formatTime(stats.last_updated) : '-' }}
    </div>
  </div>
</template>
