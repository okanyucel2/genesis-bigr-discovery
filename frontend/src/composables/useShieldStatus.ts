import { ref, readonly, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type { ShieldStatus } from '@/types/home-dashboard'
import type { GuardianStatusResponse } from '@/types/api'

const defaultStatus: ShieldStatus = {
  installed: false,
  online: false,
  deployment: 'none',
  capabilities: { dns: false, firewall: false },
}

export function useShieldStatus() {
  const shieldStatus = ref<ShieldStatus>({ ...defaultStatus })
  const guardianData = ref<GuardianStatusResponse | null>(null)

  async function fetchShieldStatus(): Promise<void> {
    try {
      const res = await bigrApi.getGuardianStatus()
      const data = res.data
      guardianData.value = data

      shieldStatus.value = {
        installed: true,
        online: data.guardian_active,
        deployment: 'standalone',
        capabilities: {
          dns: data.dns_filtering,
          firewall: false,
        },
      }
    } catch {
      // Guardian API unreachable — shield not available
      shieldStatus.value = { ...defaultStatus }
      guardianData.value = null
    }
  }

  function setShieldStatus(status: ShieldStatus): void {
    shieldStatus.value = status
  }

  const guardianBlockedCount = computed(
    () => guardianData.value?.stats?.blocked_queries ?? 0,
  )

  const guardianDomainCount = computed(
    () => guardianData.value?.blocked_domains_count ?? 0,
  )

  return {
    shieldStatus: readonly(shieldStatus),
    guardianData: readonly(guardianData),
    guardianBlockedCount,
    guardianDomainCount,
    fetchShieldStatus,
    setShieldStatus,
  }
}
