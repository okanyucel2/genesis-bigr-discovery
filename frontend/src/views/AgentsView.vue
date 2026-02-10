<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Radio, Wifi, MapPin, Clock, RefreshCw, Play } from 'lucide-vue-next'
import { useAgents } from '@/composables/useAgents'
import AgentDetailModal from '@/components/agents/AgentDetailModal.vue'
import type { Agent } from '@/types/api'
import { bigrApi } from '@/lib/api'

const { agents, loading, error, fetchAgents } = useAgents()

const selectedAgent = ref<Agent | null>(null)
const quickScanning = ref<string | null>(null) // agent id being quick-scanned

const onlineCount = computed(() => agents.value.filter(a => a.status === 'online').length)
const totalCount = computed(() => agents.value.length)

function statusColor(status: string): string {
  switch (status) {
    case 'online': return 'text-emerald-400'
    case 'stale': return 'text-amber-400'
    default: return 'text-slate-500'
  }
}

function statusDot(status: string): string {
  switch (status) {
    case 'online': return 'bg-emerald-400'
    case 'stale': return 'bg-amber-400'
    default: return 'bg-slate-500'
  }
}

function timeAgo(iso: string | null): string {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

async function quickScan(agent: Agent, event: Event) {
  event.stopPropagation()
  if (quickScanning.value) return
  if (!agent.subnets.length) {
    // No subnets — open modal instead
    selectedAgent.value = agent
    return
  }
  quickScanning.value = agent.id
  try {
    await bigrApi.createAgentCommand(agent.id)
  } catch {
    // Silently fail quick scan — user can use modal for details
  } finally {
    quickScanning.value = null
  }
}

onMounted(fetchAgents)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Remote Agents</h1>
        <p class="mt-1 text-sm text-slate-400">
          {{ onlineCount }} / {{ totalCount }} online
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-slate-700 px-4 py-2 text-sm text-white hover:bg-slate-600"
        @click="fetchAgents"
      >
        <RefreshCw class="h-4 w-4" />
        Refresh
      </button>
    </div>

    <div v-if="loading && !agents.length" class="flex items-center justify-center py-12">
      <div class="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
    </div>

    <div v-else-if="error && !agents.length" class="glass-card rounded-xl p-6 text-center">
      <p class="text-rose-400">{{ error }}</p>
    </div>

    <div v-else-if="!agents.length" class="glass-card rounded-xl p-8 text-center">
      <Radio class="mx-auto h-12 w-12 text-slate-500" />
      <p class="mt-4 text-lg text-slate-300">No agents registered</p>
      <p class="mt-1 text-sm text-slate-500">
        Use <code class="rounded bg-slate-700 px-1.5 py-0.5 text-cyan-400">bigr agent register</code>
        to connect a remote scanner.
      </p>
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
          <span :class="[statusColor(agent.status), 'text-xs font-medium uppercase']">
            {{ agent.status }}
          </span>
        </div>

        <div class="mt-4 space-y-2 text-sm">
          <div class="flex items-center gap-2 text-slate-300">
            <MapPin class="h-3.5 w-3.5 text-slate-500" />
            <span>{{ agent.site_name || 'No site' }}</span>
            <span v-if="agent.location" class="text-slate-500">{{ agent.location }}</span>
          </div>

          <div class="flex items-center gap-2 text-slate-300">
            <Clock class="h-3.5 w-3.5 text-slate-500" />
            <span>Last seen: {{ timeAgo(agent.last_seen) }}</span>
          </div>

          <div v-if="agent.subnets.length" class="flex items-center gap-2 text-slate-300">
            <Wifi class="h-3.5 w-3.5 text-slate-500" />
            <span>{{ agent.subnets.join(', ') }}</span>
          </div>

          <div class="flex items-center justify-between">
            <div v-if="agent.version" class="text-xs text-slate-500">
              v{{ agent.version }}
            </div>
            <button
              v-if="agent.status === 'online'"
              :disabled="quickScanning === agent.id"
              :class="[
                'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all',
                quickScanning === agent.id
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 hover:text-cyan-300',
              ]"
              @click="quickScan(agent, $event)"
            >
              <Play v-if="quickScanning !== agent.id" class="h-3 w-3" />
              <div v-else class="h-3 w-3 animate-spin rounded-full border border-cyan-400 border-t-transparent" />
              {{ quickScanning === agent.id ? 'Queued' : 'Scan Now' }}
            </button>
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
