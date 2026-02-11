import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'
import MobileTabBar from '@/components/layout/MobileTabBar.vue'

function makeRouter() {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', name: 'home', component: { template: '<div />' } },
      { path: '/family', name: 'family', component: { template: '<div />' } },
      { path: '/assets', name: 'assets', component: { template: '<div />' } },
      { path: '/settings', name: 'settings', component: { template: '<div />' } },
    ],
  })
}

describe('MobileTabBar', () => {
  it('renders 4 tabs', async () => {
    const router = makeRouter()
    router.push('/')
    await router.isReady()

    const wrapper = mount(MobileTabBar, {
      global: { plugins: [router] },
    })

    const buttons = wrapper.findAll('button')
    expect(buttons).toHaveLength(4)
  })

  it('shows correct tab labels', async () => {
    const router = makeRouter()
    router.push('/')
    await router.isReady()

    const wrapper = mount(MobileTabBar, {
      global: { plugins: [router] },
    })

    expect(wrapper.text()).toContain('Ana')
    expect(wrapper.text()).toContain('Ailem')
    expect(wrapper.text()).toContain('Cihazlar')
    expect(wrapper.text()).toContain('Ayarlar')
  })

  it('highlights active tab', async () => {
    const router = makeRouter()
    router.push('/')
    await router.isReady()

    const wrapper = mount(MobileTabBar, {
      global: { plugins: [router] },
    })

    const buttons = wrapper.findAll('button')
    // First button (home) should have cyan text
    expect(buttons[0]!.classes()).toContain('text-cyan-400')
    // Other buttons should have slate text
    expect(buttons[1]!.classes()).toContain('text-slate-500')
  })

  it('has md:hidden class for desktop hiding', async () => {
    const router = makeRouter()
    router.push('/')
    await router.isReady()

    const wrapper = mount(MobileTabBar, {
      global: { plugins: [router] },
    })

    expect(wrapper.find('nav').classes()).toContain('md:hidden')
  })
})
