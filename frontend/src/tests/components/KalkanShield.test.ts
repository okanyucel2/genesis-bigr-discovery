import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import KalkanShield from '@/components/home/KalkanShield.vue'
import type { KalkanData } from '@/types/home-dashboard'

function makeKalkan(overrides: Partial<KalkanData> = {}): KalkanData {
  return {
    score: 87,
    state: 'green',
    message: 'Aileniz guvende. 4 cihaz koruma altinda.',
    deviceCount: 4,
    blockedThisMonth: 47,
    complianceScore: 85,
    riskScore: 25,
    firewallScore: 100,
    ...overrides,
  }
}

describe('KalkanShield', () => {
  it('renders green state correctly', () => {
    const wrapper = mount(KalkanShield, {
      props: { data: makeKalkan() },
    })

    expect(wrapper.text()).toContain('87')
    expect(wrapper.text()).toContain('guvende')
    expect(wrapper.find('.kalkan-green').exists()).toBe(true)
  })

  it('renders yellow state correctly', () => {
    const wrapper = mount(KalkanShield, {
      props: { data: makeKalkan({ score: 65, state: 'yellow', message: 'Dikkat gerektiren durumlar var. 4 cihaz izleniyor.' }) },
    })

    expect(wrapper.text()).toContain('65')
    expect(wrapper.text()).toContain('Dikkat')
    expect(wrapper.find('.kalkan-yellow').exists()).toBe(true)
  })

  it('renders red state correctly', () => {
    const wrapper = mount(KalkanShield, {
      props: { data: makeKalkan({ score: 30, state: 'red', message: 'Acil mudahale gerekiyor! 4 cihaz risk altinda.' }) },
    })

    expect(wrapper.text()).toContain('30')
    expect(wrapper.text()).toContain('Acil')
    expect(wrapper.find('.kalkan-red').exists()).toBe(true)
  })

  it('displays micro data row', () => {
    const wrapper = mount(KalkanShield, {
      props: { data: makeKalkan() },
    })

    expect(wrapper.text()).toContain('Skor:')
    expect(wrapper.text()).toContain('Cihaz:')
    expect(wrapper.text()).toContain('Engellenen:')
    expect(wrapper.text()).toContain('47')
  })
})
