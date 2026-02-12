import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import SeverityBadge from '@/components/shared/SeverityBadge.vue'

describe('SeverityBadge', () => {
  const severityLevels = [
    { severity: 'critical', label: 'Kritik', color: 'text-red-400' },
    { severity: 'high', label: 'Yüksek', color: 'text-orange-400' },
    { severity: 'medium', label: 'Orta', color: 'text-yellow-400' },
    { severity: 'low', label: 'Düşük', color: 'text-blue-400' },
    { severity: 'none', label: 'Yok', color: 'text-gray-400' },
  ]

  it.each(severityLevels)(
    'renders correct text for severity "$severity"',
    ({ severity, label }) => {
      const wrapper = mount(SeverityBadge, {
        props: { severity },
      })
      expect(wrapper.text()).toContain(label)
    },
  )

  it.each(severityLevels)(
    'applies correct color class for severity "$severity"',
    ({ severity, color }) => {
      const wrapper = mount(SeverityBadge, {
        props: { severity },
      })
      const classes = wrapper.find('span').classes().join(' ')
      expect(classes).toContain(color)
    },
  )

  it('renders score when provided', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'critical', score: 9.8 },
    })
    expect(wrapper.text()).toContain('9.8')
  })

  it('does not render score when not provided', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'high' },
    })
    expect(wrapper.text()).toBe('Yüksek')
  })

  it('handles case-insensitive severity input', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'CRITICAL' },
    })
    expect(wrapper.text()).toContain('Kritik')
    const classes = wrapper.find('span').classes().join(' ')
    expect(classes).toContain('text-red-400')
  })

  it('falls back to "Yok" for unknown severity', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'unknown' },
    })
    expect(wrapper.text()).toContain('Yok')
    const classes = wrapper.find('span').classes().join(' ')
    expect(classes).toContain('text-gray-400')
  })
})
