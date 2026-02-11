import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ChatBubble from '@/components/onboarding/ChatBubble.vue'
import DeviceIcon from '@/components/onboarding/DeviceIcon.vue'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    startOnboarding: vi.fn(),
    completeOnboarding: vi.fn(),
  },
}))

describe('ChatBubble', () => {
  it('renders bigr message on left', () => {
    const wrapper = mount(ChatBubble, {
      props: { sender: 'bigr', message: 'Merhaba!' },
    })

    expect(wrapper.text()).toContain('Merhaba!')
    expect(wrapper.find('.justify-start').exists()).toBe(true)
  })

  it('renders user message on right', () => {
    const wrapper = mount(ChatBubble, {
      props: { sender: 'user', message: 'Evet!' },
    })

    expect(wrapper.text()).toContain('Evet!')
    expect(wrapper.find('.justify-end').exists()).toBe(true)
  })

  it('applies animation class', () => {
    const wrapper = mount(ChatBubble, {
      props: { sender: 'bigr', message: 'Test', animated: true },
    })

    expect(wrapper.find('.chat-fade-in').exists()).toBe(true)
  })
})

describe('DeviceIcon', () => {
  it('renders correct icon for device type', () => {
    const wrapper = mount(DeviceIcon, {
      props: { deviceType: 'phone' },
    })

    expect(wrapper.text()).toBe('📱')
  })

  it('renders unknown icon for unrecognized type', () => {
    const wrapper = mount(DeviceIcon, {
      props: { deviceType: 'xyz' },
    })

    expect(wrapper.text()).toBe('❓')
  })

  it('applies size class', () => {
    const wrapper = mount(DeviceIcon, {
      props: { deviceType: 'phone', size: 'lg' },
    })

    expect(wrapper.find('.text-3xl').exists()).toBe(true)
  })
})
