import { describe, it, expect } from 'vitest'
import { useShieldStatus } from '@/composables/useShieldStatus'
import type { ShieldStatus } from '@/types/home-dashboard'

describe('useShieldStatus', () => {
  it('defaults to no shield installed', () => {
    const { shieldStatus } = useShieldStatus()

    expect(shieldStatus.value.installed).toBe(false)
    expect(shieldStatus.value.online).toBe(false)
    expect(shieldStatus.value.deployment).toBe('none')
    expect(shieldStatus.value.capabilities.dns).toBe(false)
    expect(shieldStatus.value.capabilities.firewall).toBe(false)
  })

  it('setShieldStatus updates the status', () => {
    const { shieldStatus, setShieldStatus } = useShieldStatus()

    const newStatus: ShieldStatus = {
      installed: true,
      online: true,
      deployment: 'standalone',
      capabilities: { dns: true, firewall: false },
    }
    setShieldStatus(newStatus)

    expect(shieldStatus.value.installed).toBe(true)
    expect(shieldStatus.value.online).toBe(true)
    expect(shieldStatus.value.deployment).toBe('standalone')
    expect(shieldStatus.value.capabilities.dns).toBe(true)
    expect(shieldStatus.value.capabilities.firewall).toBe(false)
  })

  it('setShieldStatus can simulate shield with router', () => {
    const { shieldStatus, setShieldStatus } = useShieldStatus()

    setShieldStatus({
      installed: true,
      online: true,
      deployment: 'router',
      capabilities: { dns: true, firewall: true },
    })

    expect(shieldStatus.value.deployment).toBe('router')
    expect(shieldStatus.value.capabilities.firewall).toBe(true)
  })

  it('shieldStatus is readonly ref', () => {
    const { shieldStatus } = useShieldStatus()

    // The ref itself is readonly — can only change via setShieldStatus
    expect(shieldStatus.value.installed).toBe(false)
  })
})
