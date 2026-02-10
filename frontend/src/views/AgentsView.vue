<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { Radio, Wifi, WifiOff, MapPin, Clock, RefreshCw } from 'lucide-vue-next'
import { useAgents } from '@/composables/useAgents'

const { agents, loading, error, fetchAgents } = useAgents()

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
        class="glass-card rounded-xl p-5 transition-colors hover:border-cyan-500/30"
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

          <div v-if="agent.version" class="text-xs text-slate-500">
            v{{ agent.version }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
