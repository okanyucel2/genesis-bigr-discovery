import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import SeverityBadge from '@/components/shared/SeverityBadge.vue'

describe('SeverityBadge', () => {
  const severityLevels = [
    { severity: 'critical', label: 'Critical', color: 'text-red-400' },
    { severity: 'high', label: 'High', color: 'text-orange-400' },
    { severity: 'medium', label: 'Medium', color: 'text-yellow-400' },
    { severity: 'low', label: 'Low', color: 'text-blue-400' },
    { severity: 'none', label: 'None', color: 'text-gray-400' },
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
    // Only the label should be present, no decimal number
    expect(wrapper.text()).toBe('High')
  })

  it('handles case-insensitive severity input', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'CRITICAL' },
    })
    expect(wrapper.text()).toContain('Critical')
    const classes = wrapper.find('span').classes().join(' ')
    expect(classes).toContain('text-red-400')
  })

  it('falls back to "None" for unknown severity', () => {
    const wrapper = mount(SeverityBadge, {
      props: { severity: 'unknown' },
    })
    expect(wrapper.text()).toContain('None')
    const classes = wrapper.find('span').classes().join(' ')
    expect(classes).toContain('text-gray-400')
  })
})
