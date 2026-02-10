<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  RefreshCw,
  Loader2,
  AlertTriangle,
  Wrench,
  Shield,
  Activity,
  CheckCircle,
  XCircle,
  Zap,
  Clock,
} from 'lucide-vue-next'
import { useRemediation } from '@/composables/useRemediation'
import type { RemediationAction } from '@/types/api'

const {
  plan,
  deadmanStatus,
  loading,
  executing,
  error,
  autoFixableActions,
  fetchPlan,
  executeAction,
  executeAllAutoFixable,
  fetchDeadManStatus,
  forceDeadManCheck,
} = useRemediation()

const activeTab = ref<'actions' | 'deadman'>('actions')
const executingAll = ref(false)

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  low: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

const severityDotColors: Record<string, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-slate-400',
}

const actionsByIp = computed(() => {
  if (!plan.value) return {}
  const grouped: Record<string, RemediationAction[]> = {}
  for (const action of plan.value.actions) {
    const key = action.target_ip || 'network'
    if (!grouped[key]) grouped[key] = []
    grouped[key].push(action)
  }
  return grouped
})

async function handleExecuteAction(actionId: string) {
  await executeAction(actionId)
}

async function handleExecuteAll() {
  executingAll.value = true
  await executeAllAutoFixable()
  executingAll.value = false
}

async function refresh() {
  await Promise.all([fetchPlan(), fetchDeadManStatus()])
}

onMounted(() => {
  refresh()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Onarim Merkezi</h1>
        <p class="mt-1 text-sm text-slate-400">
          Tehditleri tespit et, tek tikla onar. Sen kahveni yudumla, gerisi bizde.
        </p>
      </div>
      <div class="flex items-center gap-3">
        <button
          v-if="autoFixableActions.length > 0"
          class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          :disabled="executingAll || loading"
          @click="handleExecuteAll"
        >
          <Zap class="h-4 w-4" :class="{ 'animate-pulse': executingAll }" />
          Hepsini Onar ({{ autoFixableActions.length }})
        </button>
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="refresh"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Yenile
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !plan"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Onarim plani hazirlaniyor...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && !plan"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Veri Yuklenemedi</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="refresh"
      >
        Tekrar Dene
      </button>
    </div>

    <!-- Content -->
    <template v-else-if="plan">
      <!-- Overview Cards -->
      <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-white">{{ plan.total_actions }}</div>
          <div class="mt-1 text-xs text-slate-400">Toplam Aksiyon</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-red-500/20">
          <div class="text-3xl font-bold text-red-400">{{ plan.critical_count }}</div>
          <div class="mt-1 text-xs text-slate-400">Kritik</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-cyan-500/20">
          <div class="text-3xl font-bold text-cyan-400">{{ plan.auto_fixable_count }}</div>
          <div class="mt-1 text-xs text-slate-400">Otomatik Onarilabilir</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-slate-300">{{ plan.ai_tier_used }}</div>
          <div class="mt-1 text-xs text-slate-400">Analiz Motoru</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex gap-1 rounded-lg bg-white/5 p-1">
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'actions' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'actions'"
        >
          <Wrench class="h-4 w-4" />
          Onarim Aksiyonlari
        </button>
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'deadman' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'deadman'; fetchDeadManStatus()"
        >
          <Activity class="h-4 w-4" />
          Olum Anahtari
        </button>
      </div>

      <!-- Actions Tab -->
      <div v-if="activeTab === 'actions'">
        <!-- Empty state -->
        <div
          v-if="plan.total_actions === 0"
          class="glass-card rounded-xl p-12 text-center"
        >
          <Shield class="mx-auto h-12 w-12 text-emerald-400" />
          <h2 class="mt-4 text-lg font-semibold text-white">Her Sey Yolunda!</h2>
          <p class="mt-2 text-sm text-slate-400">
            Agin temiz gorunuyor. Onarim gerektiren bir durum bulunamadi.
          </p>
        </div>

        <!-- Actions grouped by IP -->
        <div v-else class="space-y-6">
          <div
            v-for="(actions, ip) in actionsByIp"
            :key="ip"
            class="glass-card rounded-xl border border-white/5 overflow-hidden"
          >
            <!-- IP Header -->
            <div class="flex items-center justify-between border-b border-white/5 px-5 py-3">
              <div class="flex items-center gap-3">
                <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10">
                  <Activity class="h-4 w-4 text-cyan-400" />
                </div>
                <div>
                  <span class="font-mono text-sm font-medium text-white">{{ ip }}</span>
                  <span class="ml-2 text-xs text-slate-500">{{ actions.length }} aksiyon</span>
                </div>
              </div>
            </div>

            <!-- Actions List -->
            <div class="divide-y divide-white/5">
              <div
                v-for="action in actions"
                :key="action.id"
                class="flex items-center gap-4 px-5 py-4 transition-colors hover:bg-white/[0.02]"
              >
                <!-- Severity dot -->
                <div
                  class="h-2.5 w-2.5 shrink-0 rounded-full"
                  :class="severityDotColors[action.severity] || 'bg-slate-400'"
                />

                <!-- Content -->
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-white">{{ action.title_tr }}</span>
                    <span
                      class="inline-flex rounded-md border px-1.5 py-0.5 text-[10px] font-medium"
                      :class="severityColors[action.severity] || severityColors.low"
                    >
                      {{ action.severity }}
                    </span>
                    <span
                      v-if="action.auto_fixable"
                      class="inline-flex items-center gap-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 text-[10px] font-medium text-cyan-400"
                    >
                      <Zap class="h-2.5 w-2.5" />
                      Otomatik
                    </span>
                  </div>
                  <p class="mt-1 text-xs text-slate-500">{{ action.description_tr }}</p>
                  <p v-if="action.target_port" class="mt-0.5 text-xs text-slate-600">
                    Port: {{ action.target_port }} | {{ action.action_type }}
                  </p>
                  <p class="mt-1 text-xs text-amber-500/80">{{ action.estimated_impact }}</p>
                </div>

                <!-- Action button -->
                <button
                  v-if="action.auto_fixable"
                  class="flex shrink-0 items-center gap-1.5 rounded-lg bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-500/20"
                  :disabled="executing === action.id"
                  @click="handleExecuteAction(action.id)"
                >
                  <Loader2 v-if="executing === action.id" class="h-3 w-3 animate-spin" />
                  <Wrench v-else class="h-3 w-3" />
                  Onar
                </button>
                <span
                  v-else
                  class="shrink-0 rounded-lg bg-white/5 px-3 py-1.5 text-xs text-slate-500"
                >
                  Manuel
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Dead Man Switch Tab -->
      <div v-if="activeTab === 'deadman'" class="space-y-4">
        <div v-if="!deadmanStatus" class="flex flex-col items-center justify-center py-12">
          <Loader2 class="h-6 w-6 animate-spin text-cyan-400" />
          <p class="mt-2 text-sm text-slate-400">Ajan durumlari kontrol ediliyor...</p>
        </div>

        <template v-else>
          <!-- Dead Man Summary -->
          <div class="glass-card rounded-xl border border-white/5 p-5">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-medium text-white">Olum Anahtari Durumu</h3>
                <p class="mt-1 text-xs text-slate-400">{{ deadmanStatus.summary_tr }}</p>
              </div>
              <button
                class="flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:bg-white/10"
                @click="forceDeadManCheck"
              >
                <RefreshCw class="h-3 w-3" />
                Zorla Kontrol
              </button>
            </div>
            <div class="mt-4 grid grid-cols-3 gap-3">
              <div class="rounded-lg bg-white/5 p-3 text-center">
                <div class="text-xl font-bold text-white">{{ deadmanStatus.total_agents }}</div>
                <div class="text-[10px] text-slate-500">Toplam Ajan</div>
              </div>
              <div class="rounded-lg bg-emerald-500/10 p-3 text-center">
                <div class="text-xl font-bold text-emerald-400">{{ deadmanStatus.alive_count }}</div>
                <div class="text-[10px] text-slate-500">Aktif</div>
              </div>
              <div class="rounded-lg bg-red-500/10 p-3 text-center">
                <div class="text-xl font-bold text-red-400">{{ deadmanStatus.alert_count }}</div>
                <div class="text-[10px] text-slate-500">Sessiz</div>
              </div>
            </div>
          </div>

          <!-- Agent Status List -->
          <div
            v-for="agentStatus in deadmanStatus.statuses"
            :key="agentStatus.agent_id"
            class="glass-card flex items-center gap-4 rounded-xl border p-4 transition-colors"
            :class="agentStatus.is_alive ? 'border-emerald-500/20' : 'border-red-500/30 bg-red-500/5'"
          >
            <div
              class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
              :class="agentStatus.is_alive ? 'bg-emerald-500/10' : 'bg-red-500/10'"
            >
              <CheckCircle v-if="agentStatus.is_alive" class="h-5 w-5 text-emerald-400" />
              <XCircle v-else class="h-5 w-5 text-red-400" />
            </div>

            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-sm font-medium text-white">{{ agentStatus.agent_name || agentStatus.agent_id }}</span>
                <span
                  class="inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium"
                  :class="agentStatus.is_alive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'"
                >
                  {{ agentStatus.is_alive ? 'Aktif' : 'Sessiz' }}
                </span>
              </div>
              <div class="mt-1 flex items-center gap-3 text-xs text-slate-500">
                <span v-if="agentStatus.last_heartbeat" class="flex items-center gap-1">
                  <Clock class="h-3 w-3" />
                  Son sinyal: {{ agentStatus.minutes_since_heartbeat?.toFixed(0) }} dk once
                </span>
                <span v-else class="text-amber-500">Hic sinyal alinmadi</span>
              </div>
            </div>

            <div v-if="agentStatus.alert_triggered" class="shrink-0">
              <span class="flex items-center gap-1 rounded-lg bg-red-500/10 px-2 py-1 text-xs font-medium text-red-400">
                <AlertTriangle class="h-3 w-3" />
                Uyari
              </span>
            </div>
          </div>

          <!-- Empty state for deadman -->
          <div
            v-if="deadmanStatus.statuses.length === 0"
            class="glass-card rounded-xl p-12 text-center"
          >
            <Activity class="mx-auto h-12 w-12 text-slate-600" />
            <h2 class="mt-4 text-lg font-semibold text-white">Kayitli Ajan Yok</h2>
            <p class="mt-2 text-sm text-slate-400">
              Henuz kayitli ajan bulunamadi. Bir ajan kaydettiginizde buradan takip edebilirsiniz.
            </p>
          </div>
        </template>
      </div>
    </template>
  </div>
</template>
