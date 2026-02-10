import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'

export type NetworkType = 'home' | 'work' | 'cafe' | 'other'

export interface NetworkInfo {
  network_id: string | null
  ssid: string | null
  gateway_ip: string | null
  gateway_mac: string | null
  safety_score: number
  risk_factors: string[]
  safety_message: string
  safety_detail: string
  known_network: boolean
  open_ports: number[]
  device_count: number
}

export const useOnboardingStore = defineStore('onboarding', () => {
  const currentStep = ref(0) // 0=welcome, 1=scan, 2=name, 3=ready
  const networkInfo = ref<NetworkInfo | null>(null)
  const networkName = ref('')
  const networkType = ref<NetworkType>('home')
  const isScanning = ref(false)
  const isComplete = ref(false)
  const safetyMessage = ref('')
  const safetyDetail = ref('')
  const error = ref<string | null>(null)

  const safetyScore = computed(() => networkInfo.value?.safety_score ?? 0)

  const safetyLevel = computed<'safe' | 'warning' | 'danger'>(() => {
    const score = safetyScore.value
    if (score >= 0.75) return 'safe'
    if (score >= 0.50) return 'warning'
    return 'danger'
  })

  async function startScan() {
    isScanning.value = true
    error.value = null
    try {
      const res = await bigrApi.startOnboarding()
      const data = res.data
      networkInfo.value = {
        network_id: data.network_id,
        ssid: data.ssid,
        gateway_ip: data.gateway_ip,
        gateway_mac: data.gateway_mac,
        safety_score: data.safety_score,
        risk_factors: data.risk_factors,
        safety_message: data.safety_message,
        safety_detail: data.safety_detail,
        known_network: data.known_network,
        open_ports: data.open_ports,
        device_count: data.device_count,
      }
      safetyMessage.value = data.safety_message
      safetyDetail.value = data.safety_detail
      currentStep.value = 1
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Scan failed'
      error.value = message
      // Provide fallback data so user is not blocked
      networkInfo.value = {
        network_id: null,
        ssid: null,
        gateway_ip: null,
        gateway_mac: null,
        safety_score: 0.80,
        risk_factors: [],
        safety_message: 'Agini henuz tam taniyamadim ama korumaya basladim.',
        safety_detail: 'Arka planda calismaya devam ediyorum.',
        known_network: false,
        open_ports: [],
        device_count: 0,
      }
      safetyMessage.value = networkInfo.value.safety_message
      safetyDetail.value = networkInfo.value.safety_detail
      currentStep.value = 1
    } finally {
      isScanning.value = false
    }
  }

  async function submitNetworkName(name: string, type: NetworkType) {
    networkName.value = name
    networkType.value = type
    error.value = null

    const netId = networkInfo.value?.network_id
    if (netId) {
      try {
        await bigrApi.nameNetwork(netId, name, type)
      } catch {
        // Non-blocking -- naming is a nice-to-have
      }
    }
    currentStep.value = 3
  }

  async function completeOnboarding() {
    error.value = null
    try {
      await bigrApi.completeOnboarding()
    } catch {
      // Non-blocking
    }
    isComplete.value = true
  }

  function goToStep(step: number) {
    if (step >= 0 && step <= 3) {
      currentStep.value = step
    }
  }

  function $reset() {
    currentStep.value = 0
    networkInfo.value = null
    networkName.value = ''
    networkType.value = 'home'
    isScanning.value = false
    isComplete.value = false
    safetyMessage.value = ''
    safetyDetail.value = ''
    error.value = null
  }

  return {
    currentStep,
    networkInfo,
    networkName,
    networkType,
    isScanning,
    isComplete,
    safetyMessage,
    safetyDetail,
    safetyScore,
    safetyLevel,
    error,
    startScan,
    submitNetworkName,
    completeOnboarding,
    goToStep,
    $reset,
  }
})
