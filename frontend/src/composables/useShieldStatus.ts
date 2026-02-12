import { ref, readonly } from 'vue'
import type { ShieldStatus } from '@/types/home-dashboard'

const defaultStatus: ShieldStatus = {
  installed: false,
  online: false,
  deployment: 'none',
  capabilities: { dns: false, firewall: false },
}

export function useShieldStatus() {
  const shieldStatus = ref<ShieldStatus>({ ...defaultStatus })

  async function fetchShieldStatus(): Promise<void> {
    // In production, this would call GET /api/shield/status
    // For now, return default (no shield installed)
    // Demo mode scenarios can override via setShieldStatus
    try {
      // TODO: const res = await bigrApi.getShieldStatus()
      // shieldStatus.value = res.data
    } catch {
      // Shield unreachable → mark as offline
      if (shieldStatus.value.installed) {
        shieldStatus.value = { ...shieldStatus.value, online: false }
      }
    }
  }

  function setShieldStatus(status: ShieldStatus): void {
    shieldStatus.value = status
  }

  return {
    shieldStatus: readonly(shieldStatus),
    fetchShieldStatus,
    setShieldStatus,
  }
}
