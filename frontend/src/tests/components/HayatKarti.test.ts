import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import HayatKarti from '@/components/home/HayatKarti.vue'

describe('HayatKarti', () => {
  it('renders icon and title', () => {
    const wrapper = mount(HayatKarti, {
      props: { title: 'Verilerim', icon: '🔐' },
      slots: { default: '<p>Content here</p>' },
    })

    expect(wrapper.text()).toContain('🔐')
    expect(wrapper.text()).toContain('Verilerim')
    expect(wrapper.text()).toContain('Content here')
  })

  it('shows ok status dot by default', () => {
    const wrapper = mount(HayatKarti, {
      props: { title: 'Test', icon: '🏠' },
    })

    expect(wrapper.find('.bg-emerald-400').exists()).toBe(true)
  })

  it('shows warning status dot', () => {
    const wrapper = mount(HayatKarti, {
      props: { title: 'Test', icon: '🏠', status: 'warning' },
    })

    expect(wrapper.find('.bg-amber-400').exists()).toBe(true)
  })

  it('shows danger status dot with pulse', () => {
    const wrapper = mount(HayatKarti, {
      props: { title: 'Test', icon: '🏠', status: 'danger' },
    })

    const dot = wrapper.find('.bg-rose-400')
    expect(dot.exists()).toBe(true)
    expect(dot.classes()).toContain('animate-pulse')
  })

  it('applies warning border class', () => {
    const wrapper = mount(HayatKarti, {
      props: { title: 'Test', icon: '🏠', status: 'warning' },
    })

    expect(wrapper.find('.border-amber-500\\/30').exists()).toBe(true)
  })
})
