import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineItem from '@/components/home/TimelineItem.vue'
import type { TimelineItem as TimelineItemType } from '@/types/home-dashboard'

function makeItem(overrides: Partial<TimelineItemType> = {}): TimelineItemType {
  return {
    id: 'test_1',
    source: 'firewall',
    severity: 'medium',
    message: 'Test mesaji',
    detail: 'Detay bilgisi',
    timestamp: new Date().toISOString(),
    icon: '🛡️',
    ...overrides,
  }
}

describe('TimelineItem', () => {
  it('renders message and icon', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    expect(wrapper.text()).toContain('Test mesaji')
    expect(wrapper.text()).toContain('🛡️')
  })

  it('applies critical severity class', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ severity: 'critical' }), expanded: false },
    })

    expect(wrapper.find('.border-l-rose-500').exists()).toBe(true)
  })

  it('applies medium severity class', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ severity: 'medium' }), expanded: false },
    })

    expect(wrapper.find('.border-l-yellow-500').exists()).toBe(true)
  })

  it('shows Detay button when detail exists', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    expect(wrapper.text()).toContain('Detay')
  })

  it('hides Detay button when no detail', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: null }), expanded: false },
    })

    expect(wrapper.text()).not.toContain('Detay')
  })

  it('shows detail content when expanded', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: true },
    })

    expect(wrapper.text()).toContain('Detay bilgisi')
    expect(wrapper.text()).toContain('Gizle')
  })

  it('emits toggle on click', async () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    await wrapper.find('.timeline-item').trigger('click')
    expect(wrapper.emitted('toggle')).toHaveLength(1)
  })
})
