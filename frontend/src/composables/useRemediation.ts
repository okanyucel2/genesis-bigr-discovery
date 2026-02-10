import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  RemediationPlan,
  RemediationHistoryResponse,
  DeadManStatusResponse,
} from '@/types/api'

export function useRemediation() {
  const plan = ref<RemediationPlan | null>(null)
  const history = ref<RemediationHistoryResponse | null>(null)
  const deadmanStatus = ref<DeadManStatusResponse | null>(null)
  const loading = ref(false)
  const executing = ref<string | null>(null) // action_id currently executing
  const error = ref<string | null>(null)

  const criticalActions = computed(() =>
    plan.value?.actions.filter((a) => a.severity === 'critical') ?? [],
  )
  const highActions = computed(() =>
    plan.value?.actions.filter((a) => a.severity === 'high') ?? [],
  )
  const autoFixableActions = computed(() =>
    plan.value?.actions.filter((a) => a.auto_fixable) ?? [],
  )

  async function fetchPlan(ip?: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getRemediationPlan(ip)
      plan.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Onarim plani yuklenemedi'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function executeAction(actionId: string) {
    executing.value = actionId
    error.value = null
    try {
      const res = await bigrApi.executeRemediation(actionId)
      // Refresh plan after execution
      if (plan.value?.asset_ip) {
        await fetchPlan(plan.value.asset_ip)
      } else {
        await fetchPlan()
      }
      return res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Onarim basarisiz'
      error.value = message
      return null
    } finally {
      executing.value = null
    }
  }

  async function executeAllAutoFixable() {
    const actions = autoFixableActions.value
    const results = []
    for (const action of actions) {
      const result = await executeAction(action.id)
      results.push(result)
    }
    return results
  }

  async function fetchHistory() {
    try {
      const res = await bigrApi.getRemediationHistory()
      history.value = res.data
    } catch {
      // Silently fail for history
    }
  }

  async function fetchDeadManStatus() {
    try {
      const res = await bigrApi.getDeadManStatus()
      deadmanStatus.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function forceDeadManCheck() {
    try {
      await bigrApi.forceDeadManCheck()
      await fetchDeadManStatus()
    } catch {
      // Silently fail
    }
  }

  return {
    plan,
    history,
    deadmanStatus,
    loading,
    executing,
    error,
    criticalActions,
    highActions,
    autoFixableActions,
    fetchPlan,
    executeAction,
    executeAllAutoFixable,
    fetchHistory,
    fetchDeadManStatus,
    forceDeadManCheck,
  }
}
