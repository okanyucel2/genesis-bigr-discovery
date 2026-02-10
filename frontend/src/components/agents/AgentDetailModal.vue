<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import {
  X, Play, Clock, MapPin, Wifi, Shield,
  AlertCircle, Loader2, ChevronDown, ChevronUp,
} from 'lucide-vue-next'
import type { Agent, AgentCommand } from '@/types/api'
import { bigrApi } from '@/lib/api'
import { useCommandTracker } from '@/composables/useCommandTracker'
import CommandTracker from './CommandTracker.vue'

const props = defineProps<{
  agent: Agent
}>()

const emit = defineEmits<{
  close: []
  scanTriggered: []
}>()

// Command tracker
const tracker = useCommandTracker(props.agent.id)

// Scan config
const selectedTargets = ref<string[]>([...props.agent.subnets])
const shieldEnabled = ref(true)
const scanning = ref(false)
const scanError = ref<string | null>(null)

// Command history
const commands = ref<AgentCommand[]>([])
const loadingHistory = ref(false)
const historyExpanded = ref(false)

// Close on Escape
function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') emit('close')
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  // Auto-resume tracking if there's an active command
  tracker.resumeIfActive()
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
})

function toggleTarget(subnet: string) {
  const idx = selectedTargets.value.indexOf(subnet)
  if (idx >= 0) {
    selectedTargets.value.splice(idx, 1)
  } else {
    selectedTargets.value.push(subnet)
  }
}

async function triggerScan() {
  if (selectedTargets.value.length === 0) return
  scanning.value = true
  scanError.value = null
  try {
    const { data } = await bigrApi.createAgentCommand(
      props.agent.id,
      selectedTargets.value,
      shieldEnabled.value,
    )
    // Start tracking the command
    tracker.trackCommandById(data.command_id)
    emit('scanTriggered')
    // Refresh history
    await fetchHistory()
  } catch (err: any) {
    scanError.value = err.response?.data?.detail || err.message || 'Failed to trigger scan'
  } finally {
    scanning.value = false
  }
}

async function fetchHistory() {
  loadingHistory.value = true
  try {
    const { data } = await bigrApi.getAgentCommands(props.agent.id)
    commands.value = data.commands
  } catch {
    // silent
  } finally {
    loadingHistory.value = false
  }
}

function statusBadge(status: string): { color: string; label: string } {
  switch (status) {
    case 'pending': return { color: 'bg-amber-500/20 text-amber-400 border-amber-500/30', label: 'Pending' }
    case 'ack': return { color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', label: 'Acknowledged' }
    case 'running': return { color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30', label: 'Running' }
    case 'completed': return { color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30', label: 'Completed' }
    case 'failed': return { color: 'bg-rose-500/20 text-rose-400 border-rose-500/30', label: 'Failed' }
    default: return { color: 'bg-slate-500/20 text-slate-400 border-slate-500/30', label: status }
  }
}

function timeAgo(iso: string | null): string {
  if (!iso) return '-'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

const hasTargets = computed(() => selectedTargets.value.length > 0)

watch(() => historyExpanded.value, (expanded) => {
  if (expanded && commands.value.length === 0) {
    fetchHistory()
  }
})
</script>

<template>
  <!-- Backdrop -->
  <Teleport to="body">
    <div
      class="fixed inset-0 z-50 flex items-center justify-center p-4"
      @click.self="emit('close')"
    >
      <!-- Overlay -->
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="emit('close')" />

      <!-- Modal -->
      <div
        class="relative z-10 w-full max-w-lg overflow-hidden rounded-2xl border border-slate-700/60 bg-slate-900/95 shadow-2xl shadow-black/40"
      >
        <!-- Header -->
        <div class="flex items-center justify-between border-b border-slate-700/50 px-6 py-4">
          <div class="flex items-center gap-3">
            <div
              :class="[
                agent.status === 'online' ? 'bg-emerald-400 shadow-emerald-400/40' : agent.status === 'stale' ? 'bg-amber-400 shadow-amber-400/40' : 'bg-slate-500',
                'h-2.5 w-2.5 rounded-full shadow-lg',
              ]"
            />
            <div>
              <h2 class="text-lg font-semibold text-white">{{ agent.name }}</h2>
              <p class="text-xs text-slate-400">{{ agent.site_name || 'No site' }}</p>
            </div>
          </div>
          <button
            class="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-700 hover:text-white"
            @click="emit('close')"
          >
            <X class="h-5 w-5" />
          </button>
        </div>

        <!-- Agent info -->
        <div class="space-y-4 px-6 py-5">
          <div class="flex flex-wrap gap-3 text-sm text-slate-300">
            <div v-if="agent.location" class="flex items-center gap-1.5">
              <MapPin class="h-3.5 w-3.5 text-slate-500" />
              {{ agent.location }}
            </div>
            <div class="flex items-center gap-1.5">
              <Clock class="h-3.5 w-3.5 text-slate-500" />
              Last seen: {{ timeAgo(agent.last_seen) }}
            </div>
            <div v-if="agent.version" class="text-xs text-slate-500">
              v{{ agent.version }}
            </div>
          </div>

          <!-- Live command tracker (PhaseTimeline-inspired) -->
          <CommandTracker
            v-if="tracker.isTracking.value"
            :steps="tracker.steps.value"
            :progress-percent="tracker.progressPercent.value"
            :is-done="tracker.isDone.value"
            :targets="selectedTargets"
            :shield="shieldEnabled"
            :result="tracker.activeCommand.value?.result"
            :started-at="tracker.activeCommand.value?.started_at"
            :completed-at="tracker.activeCommand.value?.completed_at"
            @dismiss="tracker.dismiss()"
          />

          <!-- Target selection (hidden while tracking) -->
          <div v-if="!tracker.isTracking.value">
            <label class="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">
              Scan Targets
            </label>
            <div v-if="agent.subnets.length" class="flex flex-wrap gap-2">
              <button
                v-for="subnet in agent.subnets"
                :key="subnet"
                :class="[
                  'flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm transition-all',
                  selectedTargets.includes(subnet)
                    ? 'border-cyan-500/50 bg-cyan-500/15 text-cyan-300'
                    : 'border-slate-600 bg-slate-800/50 text-slate-400 hover:border-slate-500',
                ]"
                @click="toggleTarget(subnet)"
              >
                <Wifi class="h-3.5 w-3.5" />
                {{ subnet }}
              </button>
            </div>
            <p v-else class="text-sm text-slate-500">
              No subnets registered. Agent will use its default targets.
            </p>
          </div>

          <!-- Shield toggle (hidden while tracking) -->
          <div v-if="!tracker.isTracking.value" class="flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-800/30 px-4 py-3">
            <div class="flex items-center gap-2.5">
              <Shield class="h-4 w-4 text-cyan-400" />
              <div>
                <p class="text-sm font-medium text-white">Shield Security Scan</p>
                <p class="text-xs text-slate-400">Run security modules after discovery</p>
              </div>
            </div>
            <button
              :class="[
                'relative h-6 w-11 rounded-full transition-colors',
                shieldEnabled ? 'bg-cyan-500' : 'bg-slate-600',
              ]"
              @click="shieldEnabled = !shieldEnabled"
            >
              <span
                :class="[
                  'absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform',
                  shieldEnabled ? 'left-[22px]' : 'left-0.5',
                ]"
              />
            </button>
          </div>

          <!-- Error feedback -->
          <div
            v-if="scanError"
            class="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-sm text-rose-400"
          >
            <AlertCircle class="h-4 w-4 flex-shrink-0" />
            {{ scanError }}
          </div>

          <!-- Scan button (hidden while tracking) -->
          <button
            v-if="!tracker.isTracking.value"
            :disabled="scanning || !hasTargets"
            :class="[
              'flex w-full items-center justify-center gap-2 rounded-xl py-3 text-sm font-semibold transition-all',
              scanning || !hasTargets
                ? 'cursor-not-allowed bg-slate-700 text-slate-500'
                : 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20 hover:bg-cyan-400 hover:shadow-cyan-500/30 active:scale-[0.98]',
            ]"
            @click="triggerScan"
          >
            <Loader2 v-if="scanning" class="h-4 w-4 animate-spin" />
            <Play v-else class="h-4 w-4" />
            {{ scanning ? 'Triggering scan...' : 'Trigger Scan' }}
          </button>
        </div>

        <!-- Command history (collapsible) -->
        <div class="border-t border-slate-700/50">
          <button
            class="flex w-full items-center justify-between px-6 py-3 text-sm text-slate-400 transition-colors hover:text-slate-300"
            @click="historyExpanded = !historyExpanded"
          >
            <span>Command History</span>
            <ChevronUp v-if="historyExpanded" class="h-4 w-4" />
            <ChevronDown v-else class="h-4 w-4" />
          </button>

          <div v-if="historyExpanded" class="max-h-52 overflow-y-auto px-6 pb-4">
            <div v-if="loadingHistory" class="flex justify-center py-4">
              <Loader2 class="h-5 w-5 animate-spin text-slate-500" />
            </div>
            <div v-else-if="!commands.length" class="py-3 text-center text-sm text-slate-500">
              No commands yet
            </div>
            <div v-else class="space-y-2">
              <div
                v-for="cmd in commands"
                :key="cmd.id"
                class="flex items-center justify-between rounded-lg border border-slate-700/40 bg-slate-800/30 px-3 py-2 text-xs"
              >
                <div class="flex items-center gap-2">
                  <span
                    :class="[statusBadge(cmd.status).color, 'rounded-md border px-1.5 py-0.5 text-[10px] font-medium']"
                  >
                    {{ statusBadge(cmd.status).label }}
                  </span>
                  <span class="text-slate-300">
                    {{ cmd.params.targets.join(', ') }}
                  </span>
                  <span v-if="cmd.params.shield" class="text-cyan-500">
                    <Shield class="inline h-3 w-3" />
                  </span>
                </div>
                <span class="text-slate-500">{{ timeAgo(cmd.created_at) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>
