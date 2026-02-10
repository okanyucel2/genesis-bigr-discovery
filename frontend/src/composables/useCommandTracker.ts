/**
 * useCommandTracker — polls command status for real-time progress tracking.
 *
 * Inspired by Genesis useProvisioningStream pattern, adapted for HTTP polling
 * since BİGR Discovery doesn't use WebSocket.
 */

import { ref, computed, onUnmounted } from 'vue'
import type { AgentCommand } from '@/types/api'
import { bigrApi } from '@/lib/api'

export interface CommandStep {
  name: string
  status: 'pending' | 'active' | 'complete' | 'failed'
}

const POLL_INTERVAL_MS = 3000

export function useCommandTracker(agentId: string) {
  const commands = ref<AgentCommand[]>([])
  const activeCommand = ref<AgentCommand | null>(null)
  const loading = ref(false)
  let pollTimer: ReturnType<typeof setInterval> | null = null

  const isTracking = computed(() => activeCommand.value !== null)

  const steps = computed<CommandStep[]>(() => {
    const cmd = activeCommand.value
    if (!cmd) {
      return [
        { name: 'Queued', status: 'pending' },
        { name: 'Acknowledged', status: 'pending' },
        { name: 'Scanning', status: 'pending' },
        { name: 'Completed', status: 'pending' },
      ]
    }

    const statusMap: Record<string, number> = {
      pending: 0,
      ack: 1,
      running: 2,
      completed: 3,
      failed: 3,
    }
    const currentIdx = statusMap[cmd.status] ?? 0

    return [
      { name: 'Queued', status: currentIdx > 0 ? 'complete' : currentIdx === 0 ? 'active' : 'pending' },
      { name: 'Acknowledged', status: currentIdx > 1 ? 'complete' : currentIdx === 1 ? 'active' : 'pending' },
      { name: 'Scanning', status: currentIdx > 2 ? 'complete' : currentIdx === 2 ? 'active' : 'pending' },
      {
        name: cmd.status === 'failed' ? 'Failed' : 'Completed',
        status: cmd.status === 'failed' ? 'failed' : currentIdx >= 3 ? 'complete' : 'pending',
      },
    ] as CommandStep[]
  })

  const progressPercent = computed(() => {
    const cmd = activeCommand.value
    if (!cmd) return 0
    switch (cmd.status) {
      case 'pending': return 15
      case 'ack': return 35
      case 'running': return 65
      case 'completed': return 100
      case 'failed': return 100
      default: return 0
    }
  })

  const isDone = computed(() => {
    const s = activeCommand.value?.status
    return s === 'completed' || s === 'failed'
  })

  async function fetchCommands() {
    try {
      const { data } = await bigrApi.getAgentCommands(agentId)
      commands.value = data.commands
    } catch {
      // silent
    }
  }

  async function pollActiveCommand() {
    if (!activeCommand.value) return
    try {
      // History endpoint returns all statuses (including completed/failed)
      const { data } = await bigrApi.getAgentCommands(agentId)
      const found = data.commands.find(c => c.id === activeCommand.value?.id)
      if (found) {
        activeCommand.value = found
        if (found.status === 'completed' || found.status === 'failed') {
          stopPolling()
        }
      }
    } catch {
      // silent, keep polling
    }
  }

  function trackCommand(command: AgentCommand) {
    activeCommand.value = command
    startPolling()
  }

  function trackCommandById(commandId: string, initialStatus = 'pending') {
    activeCommand.value = {
      id: commandId,
      command_type: 'scan_now',
      params: { targets: [], shield: true },
      status: initialStatus,
      created_at: new Date().toISOString(),
      started_at: null,
      completed_at: null,
      result: null,
    }
    startPolling()
  }

  function startPolling() {
    stopPolling()
    pollTimer = setInterval(pollActiveCommand, POLL_INTERVAL_MS)
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  function dismiss() {
    stopPolling()
    activeCommand.value = null
  }

  onUnmounted(stopPolling)

  return {
    commands,
    activeCommand,
    loading,
    isTracking,
    steps,
    progressPercent,
    isDone,
    fetchCommands,
    trackCommand,
    trackCommandById,
    dismiss,
  }
}
