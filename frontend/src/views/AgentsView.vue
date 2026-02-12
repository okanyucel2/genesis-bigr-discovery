<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { Radio, Wifi, Clock, RefreshCw, Play, Check, X as XIcon, Terminal, Monitor, Copy, CheckCheck, Trash2 } from 'lucide-vue-next'
import { useAgents } from '@/composables/useAgents'
import AgentDetailModal from '@/components/agents/AgentDetailModal.vue'
import type { Agent } from '@/types/api'
import { bigrApi } from '@/lib/api'

const { agents, loading, error, fetchAgents } = useAgents()

const selectedAgent = ref<Agent | null>(null)

// Track active scans per agent: 'queued' | 'scanning' | 'done' | 'failed'
const scanStates = ref<Record<string, { status: string; commandId: string }>>({})
let pollTimers: Record<string, ReturnType<typeof setInterval>> = {}

const onlineCount = computed(() => agents.value.filter(a => a.status === 'online').length)
const totalCount = computed(() => agents.value.length)

function statusDot(status: string): string {
  switch (status) {
    case 'online': return 'bg-emerald-400'
    case 'stale': return 'bg-amber-400'
    case 'pending': return 'bg-blue-400 animate-pulse'
    case 'offline': return 'bg-slate-400'
    default: return 'bg-slate-500'
  }
}

function timeAgo(iso: string | null): string {
  if (!iso) return 'Hiç'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Az önce'
  if (mins < 60) return `${mins}dk önce`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}sa önce`
  return `${Math.floor(hours / 24)}g önce`
}

function scanButtonLabel(agentId: string): string {
  const state = scanStates.value[agentId]
  if (!state) return 'Tara'
  switch (state.status) {
    case 'queued': return 'Sırada'
    case 'scanning': return 'Taranıyor...'
    case 'done': return 'Tamamlandı'
    case 'failed': return 'Başarısız'
    default: return 'Tara'
  }
}

function isScanActive(agentId: string): boolean {
  const state = scanStates.value[agentId]
  return !!state && (state.status === 'queued' || state.status === 'scanning')
}

function pollCommandStatus(agentId: string, commandId: string) {
  const timer = setInterval(async () => {
    try {
      const { data } = await bigrApi.getAgentCommands(agentId)
      const cmd = data.commands.find(c => c.id === commandId)
      if (!cmd) return
      if (cmd.status === 'ack' || cmd.status === 'running') {
        scanStates.value[agentId] = { status: 'scanning', commandId }
      } else if (cmd.status === 'completed') {
        scanStates.value[agentId] = { status: 'done', commandId }
        clearInterval(timer)
        delete pollTimers[agentId]
        setTimeout(() => { delete scanStates.value[agentId] }, 4000)
      } else if (cmd.status === 'failed') {
        scanStates.value[agentId] = { status: 'failed', commandId }
        clearInterval(timer)
        delete pollTimers[agentId]
        setTimeout(() => { delete scanStates.value[agentId] }, 4000)
      }
    } catch {
      // silent
    }
  }, 3000)
  pollTimers[agentId] = timer
}

async function quickScan(agent: Agent, event: Event) {
  event.stopPropagation()
  if (isScanActive(agent.id)) return
  if (!agent.subnets.length) {
    selectedAgent.value = agent
    return
  }
  scanStates.value[agent.id] = { status: 'queued', commandId: '' }
  try {
    const { data } = await bigrApi.createAgentCommand(agent.id)
    scanStates.value[agent.id] = { status: 'queued', commandId: data.command_id }
    pollCommandStatus(agent.id, data.command_id)
  } catch {
    scanStates.value[agent.id] = { status: 'failed', commandId: '' }
    setTimeout(() => { delete scanStates.value[agent.id] }, 3000)
  }
}

// Setup commands (defined here to avoid quote issues in template)
const CMD_INSTALL = 'pip install bigr-discovery'
const CMD_START = 'bigr agent install'

// Copy-to-clipboard with feedback
const copiedCmd = ref<string | null>(null)

async function copyCommand(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedCmd.value = text
    setTimeout(() => { copiedCmd.value = null }, 2000)
  } catch {
    // fallback
  }
}

// Delete agent with confirmation
const deletingAgent = ref<string | null>(null)
async function deleteAgent(agent: Agent, event: Event) {
  event.stopPropagation()
  if (!confirm(`"${agent.name}" ajanını silmek istediğinize emin misiniz?`)) return
  deletingAgent.value = agent.id
  try {
    await bigrApi.deleteAgent(agent.id)
    await fetchAgents()
  } catch {
    // silent
  } finally {
    deletingAgent.value = null
  }
}

// Refresh with visible animation (min 600ms so user sees feedback)
const refreshing = ref(false)
async function refreshAgents() {
  refreshing.value = true
  const minDelay = new Promise(r => setTimeout(r, 600))
  await Promise.all([fetchAgents(), minDelay])
  refreshing.value = false
}

onMounted(fetchAgents)

onUnmounted(() => {
  Object.values(pollTimers).forEach(clearInterval)
  pollTimers = {}
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Tarayıcı Ajanlar</h1>
        <p class="mt-1 text-sm text-slate-400">
          {{ onlineCount }} / {{ totalCount }} çevrimiçi
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-slate-700 px-4 py-2 text-sm text-white hover:bg-slate-600 disabled:opacity-50"
        :disabled="refreshing"
        @click="refreshAgents"
      >
        <RefreshCw class="h-4 w-4 transition-transform" :class="refreshing ? 'animate-spin' : ''" />
        {{ refreshing ? 'Yenileniyor...' : 'Yenile' }}
      </button>
    </div>

    <div v-if="loading && !agents.length" class="flex items-center justify-center py-12">
      <div class="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
    </div>

    <div v-else-if="error && !agents.length" class="glass-card rounded-xl p-6 text-center">
      <p class="text-rose-400">{{ error }}</p>
    </div>

    <!-- Friendly empty state with setup guide -->
    <div v-else-if="!agents.length" class="mx-auto max-w-2xl space-y-6">
      <div class="glass-card rounded-2xl p-8 text-center">
        <div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10 ring-1 ring-cyan-500/20">
          <Radio class="h-8 w-8 text-cyan-400" />
        </div>
        <h2 class="text-xl font-semibold text-white">Henüz Ajan Yok</h2>
        <p class="mx-auto mt-2 max-w-md text-sm leading-relaxed text-slate-400">
          Ağınızdaki cihazları otomatik olarak keşfetmek için bir tarayıcı ajan kurmanız gerekiyor.
          Ajan, ağınızı periyodik olarak tarar ve yeni cihazları BİGR'e bildirir.
        </p>
      </div>

      <!-- Setup steps -->
      <div class="glass-card rounded-2xl p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">Kurulum Adımları</h3>
        <div class="space-y-4">
          <!-- Step 1: Install -->
          <div class="flex gap-4">
            <div class="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-cyan-500/15 text-sm font-bold text-cyan-400">1</div>
            <div class="flex-1">
              <p class="font-medium text-slate-200">BİGR CLI'ı yükleyin</p>
              <div class="mt-1.5 flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-800/50 px-3 py-2">
                <div class="flex items-center gap-2">
                  <Terminal class="h-4 w-4 flex-shrink-0 text-slate-500" />
                  <code class="text-sm text-cyan-400">{{ CMD_INSTALL }}</code>
                </div>
                <button
                  class="rounded p-1 text-slate-500 transition-colors hover:text-slate-300"
                  title="Kopyala"
                  @click="copyCommand(CMD_INSTALL)"
                >
                  <CheckCheck v-if="copiedCmd === CMD_INSTALL" class="h-3.5 w-3.5 text-emerald-400" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>

          <!-- Step 2: Start (auto-registers) -->
          <div class="flex gap-4">
            <div class="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-cyan-500/15 text-sm font-bold text-cyan-400">2</div>
            <div class="flex-1">
              <p class="font-medium text-slate-200">Ajanı kurun</p>
              <p class="mt-0.5 text-xs text-slate-500">Ajan arka planda çalışır, giriş yapınca otomatik başlar</p>
              <div class="mt-1.5 flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-800/50 px-3 py-2">
                <div class="flex items-center gap-2">
                  <Terminal class="h-4 w-4 flex-shrink-0 text-slate-500" />
                  <code class="text-sm text-cyan-400">{{ CMD_START }}</code>
                </div>
                <button
                  class="rounded p-1 text-slate-500 transition-colors hover:text-slate-300"
                  title="Kopyala"
                  @click="copyCommand(CMD_START)"
                >
                  <CheckCheck v-if="copiedCmd === CMD_START" class="h-3.5 w-3.5 text-emerald-400" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- What agents do -->
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div class="glass-card rounded-xl p-4 text-center">
          <Monitor class="mx-auto mb-2 h-5 w-5 text-emerald-400" />
          <p class="text-xs font-medium text-slate-300">Cihaz Keşfi</p>
          <p class="mt-0.5 text-[11px] text-slate-500">Ağdaki tüm cihazları bulur</p>
        </div>
        <div class="glass-card rounded-xl p-4 text-center">
          <Wifi class="mx-auto mb-2 h-5 w-5 text-cyan-400" />
          <p class="text-xs font-medium text-slate-300">Ağ Dolaşımı</p>
          <p class="mt-0.5 text-[11px] text-slate-500">Farklı ağları tanır</p>
        </div>
        <div class="glass-card rounded-xl p-4 text-center">
          <Clock class="mx-auto mb-2 h-5 w-5 text-amber-400" />
          <p class="text-xs font-medium text-slate-300">Periyodik Tarama</p>
          <p class="mt-0.5 text-[11px] text-slate-500">Otomatik çalışır</p>
        </div>
      </div>
    </div>

    <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="agent in agents"
        :key="agent.id"
        class="glass-card cursor-pointer rounded-xl p-5 transition-all hover:border-cyan-500/30 hover:shadow-lg hover:shadow-cyan-500/5"
        @click="selectedAgent = agent"
      >
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-3">
            <div :class="[statusDot(agent.status), 'h-2.5 w-2.5 rounded-full']" />
            <div>
              <h3 class="font-semibold text-white">{{ agent.name }}</h3>
              <p class="text-xs text-slate-400">{{ agent.id.slice(0, 8) }}...</p>
            </div>
          </div>
          <span
            :class="[
              agent.status === 'online' ? 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/30'
                : agent.status === 'pending' ? 'bg-blue-500/15 text-blue-400 ring-blue-500/30'
                : agent.status === 'stale' ? 'bg-amber-500/15 text-amber-400 ring-amber-500/30'
                : agent.status === 'offline' ? 'bg-slate-500/15 text-slate-400 ring-slate-500/30'
                : 'bg-slate-500/15 text-slate-400 ring-slate-500/30',
              'rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1',
            ]"
          >
            {{ agent.status === 'online' ? 'Aktif' : agent.status === 'pending' ? 'Başlatılmadı' : agent.status === 'stale' ? 'Bağlantı Kesildi' : 'Durduruldu' }}
          </span>
        </div>

        <div class="mt-4 space-y-2 text-sm">
          <div class="flex items-center gap-2 text-slate-300">
            <Wifi class="h-3.5 w-3.5 text-slate-500" />
            <span v-if="agent.current_network">
              {{ agent.current_network.ssid || agent.current_network.friendly_name || agent.current_network.gateway_ip }}
            </span>
            <span v-else class="text-slate-500">Ağ bilgisi yok</span>
          </div>

          <!-- Pending agent: show setup hint -->
          <div v-if="agent.status === 'pending'" class="rounded-lg border border-blue-500/20 bg-blue-500/5 px-3 py-2 text-xs text-blue-300">
            Ajanı başlatmak için: <code class="rounded bg-slate-800 px-1 text-blue-400">bigr agent install</code>
          </div>

          <template v-else>
            <div class="flex items-center gap-2 text-slate-300">
              <Clock class="h-3.5 w-3.5 text-slate-500" />
              <span>Son görülme: {{ timeAgo(agent.last_seen) }}</span>
            </div>
            <!-- Offline agent: show restart hint -->
            <div v-if="agent.status === 'offline'" class="rounded-lg border border-slate-500/20 bg-slate-500/5 px-3 py-2 text-xs text-slate-300">
              Ajan durduruldu. Tekrar başlatmak için: <code class="rounded bg-slate-800 px-1 text-slate-400">bigr agent install</code>
            </div>
            <!-- Stale agent: show restart hint -->
            <div v-else-if="agent.status === 'stale'" class="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-300">
              Ajan yanıt vermiyor. Yeniden başlatın: <code class="rounded bg-slate-800 px-1 text-amber-400">bigr agent install</code>
            </div>
          </template>

          <div v-if="agent.subnets.length" class="flex items-center gap-2 text-slate-300">
            <Wifi class="h-3.5 w-3.5 text-slate-500" />
            <span>{{ agent.subnets.join(', ') }}</span>
          </div>

          <div class="flex items-center justify-between">
            <div v-if="agent.version" class="text-xs text-slate-500">
              v{{ agent.version }}
            </div>
            <div class="flex items-center gap-2">
              <button
                v-if="agent.status !== 'online'"
                :disabled="deletingAgent === agent.id"
                class="flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs text-slate-500 transition-all hover:bg-rose-500/10 hover:text-rose-400"
                title="Ajanı sil"
                @click="deleteAgent(agent, $event)"
              >
                <Trash2 class="h-3 w-3" />
              </button>
              <button
                v-if="agent.status === 'online'"
                :disabled="isScanActive(agent.id)"
                :class="[
                  'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all',
                  scanStates[agent.id]?.status === 'done'
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : scanStates[agent.id]?.status === 'failed'
                      ? 'bg-rose-500/20 text-rose-400'
                      : isScanActive(agent.id)
                        ? 'bg-cyan-500/20 text-cyan-300'
                        : 'bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 hover:text-cyan-300',
                ]"
                @click="quickScan(agent, $event)"
              >
                <Check v-if="scanStates[agent.id]?.status === 'done'" class="h-3 w-3" />
                <XIcon v-else-if="scanStates[agent.id]?.status === 'failed'" class="h-3 w-3" />
                <div v-else-if="isScanActive(agent.id)" class="h-3 w-3 animate-spin rounded-full border border-cyan-400 border-t-transparent" />
                <Play v-else class="h-3 w-3" />
                {{ scanButtonLabel(agent.id) }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Agent detail modal -->
    <AgentDetailModal
      v-if="selectedAgent"
      :agent="selectedAgent"
      @close="selectedAgent = null"
      @scan-triggered="fetchAgents"
    />
  </div>
</template>
