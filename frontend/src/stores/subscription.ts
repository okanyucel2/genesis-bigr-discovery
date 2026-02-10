import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type { PlanInfo, SubscriptionInfo, UsageInfo, TierAccessInfo } from '@/types/api'

export const useSubscriptionStore = defineStore('subscription', () => {
  const plans = ref<PlanInfo[]>([])
  const currentSubscription = ref<SubscriptionInfo | null>(null)
  const usage = ref<UsageInfo | null>(null)
  const tierAccess = ref<TierAccessInfo | null>(null)
  const isLoading = ref(false)
  const isActivating = ref(false)
  const error = ref<string | null>(null)
  const activationMessage = ref<string | null>(null)

  const currentPlanId = computed(() => currentSubscription.value?.plan_id ?? 'free')
  const currentPlan = computed(() =>
    plans.value.find((p) => p.id === currentPlanId.value) ?? null,
  )
  const canUseL1 = computed(() => tierAccess.value?.can_use_l1 ?? false)
  const canUseL2 = computed(() => tierAccess.value?.can_use_l2 ?? false)

  async function fetchPlans() {
    isLoading.value = true
    error.value = null
    try {
      const res = await bigrApi.getPlans()
      plans.value = res.data.plans
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Planlar yuklenemedi'
    } finally {
      isLoading.value = false
    }
  }

  async function fetchCurrentSubscription() {
    error.value = null
    try {
      const res = await bigrApi.getCurrentSubscription()
      currentSubscription.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Abonelik bilgisi alinamadi'
    }
  }

  async function fetchUsage() {
    error.value = null
    try {
      const res = await bigrApi.getUsage()
      usage.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kullanim bilgisi alinamadi'
    }
  }

  async function fetchTierAccess() {
    error.value = null
    try {
      const res = await bigrApi.getTierAccess()
      tierAccess.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Tier bilgisi alinamadi'
    }
  }

  async function activatePlan(planId: string) {
    isActivating.value = true
    error.value = null
    activationMessage.value = null
    try {
      const res = await bigrApi.activatePlan(planId)
      currentSubscription.value = res.data.subscription
      activationMessage.value = res.data.message
      // Refresh tier access after plan change
      await fetchTierAccess()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Plan aktiflestirilmedi'
    } finally {
      isActivating.value = false
    }
  }

  async function loadAll() {
    await Promise.all([
      fetchPlans(),
      fetchCurrentSubscription(),
      fetchTierAccess(),
    ])
  }

  function $reset() {
    plans.value = []
    currentSubscription.value = null
    usage.value = null
    tierAccess.value = null
    isLoading.value = false
    isActivating.value = false
    error.value = null
    activationMessage.value = null
  }

  return {
    plans,
    currentSubscription,
    usage,
    tierAccess,
    isLoading,
    isActivating,
    error,
    activationMessage,
    currentPlanId,
    currentPlan,
    canUseL1,
    canUseL2,
    fetchPlans,
    fetchCurrentSubscription,
    fetchUsage,
    fetchTierAccess,
    activatePlan,
    loadAll,
    $reset,
  }
})
