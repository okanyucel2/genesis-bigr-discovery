import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import ShieldScore from '@/components/shield/ShieldScore.vue'

beforeEach(() => {
  vi.stubGlobal('requestAnimationFrame', (cb: Function) => {
    cb(performance.now() + 1100)
    return 1
  })
  vi.stubGlobal('cancelAnimationFrame', vi.fn())
})

describe('ShieldScore', () => {
  it('shows loading skeleton when loading is true', () => {
    const wrapper = mount(ShieldScore, {
      props: { score: null, grade: null, loading: true },
    })

    const pulseElements = wrapper.findAll('.animate-pulse')
    expect(pulseElements.length).toBeGreaterThanOrEqual(1)
    // Should NOT show score or "No scan yet" text
    expect(wrapper.text()).not.toContain('No scan yet')
    expect(wrapper.text()).not.toContain('/ 100')
  })

  it('shows "No scan yet" text when score is null', () => {
    const wrapper = mount(ShieldScore, {
      props: { score: null, grade: null },
    })

    expect(wrapper.text()).toContain('No scan yet')
  })

  it('renders SVG progress circle when score is provided', () => {
    const wrapper = mount(ShieldScore, {
      props: { score: 85, grade: 'A' as const },
    })

    const svg = wrapper.find('svg')
    expect(svg.exists()).toBe(true)

    // Should have two circle elements: background track + progress arc
    const circles = svg.findAll('circle')
    expect(circles.length).toBe(2)
  })

  it('shows "/ 100" text with score value', async () => {
    const wrapper = mount(ShieldScore, {
      props: { score: 72, grade: 'B+' as const },
    })

    await nextTick()

    expect(wrapper.text()).toContain('/ 100')
    // The animated displayScore should have reached the target (72)
    expect(wrapper.text()).toContain('72')
  })

  it('renders grade badge with correct grade text', () => {
    const wrapper = mount(ShieldScore, {
      props: { score: 65, grade: 'B' as const },
    })

    // Grade badge should display the grade letter
    expect(wrapper.text()).toContain('B')
    // Verify the badge has the expected styling classes
    const badge = wrapper.find('.rounded-lg.border')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toBe('B')
  })

  it('does not render grade badge when grade is null', () => {
    const wrapper = mount(ShieldScore, {
      props: { score: 50, grade: null },
    })

    // Score and "/ 100" should still render
    expect(wrapper.text()).toContain('/ 100')
    // No grade badge should be present
    const badge = wrapper.find('.rounded-lg.border')
    expect(badge.exists()).toBe(false)
  })
})
