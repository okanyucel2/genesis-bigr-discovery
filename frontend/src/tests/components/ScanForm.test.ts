import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ScanForm from '@/components/shield/ScanForm.vue'

const globalStubs = {
  global: {
    stubs: {
      Shield: true,
      Loader2: true,
    },
  },
}

describe('ScanForm', () => {
  it('renders input field and submit button', () => {
    const wrapper = mount(ScanForm, globalStubs)

    const input = wrapper.find('input[type="text"]')
    expect(input.exists()).toBe(true)
    expect(input.attributes('placeholder')).toContain('example.com')

    const submitButton = wrapper.find('button[type="submit"]')
    expect(submitButton.exists()).toBe(true)
    expect(submitButton.text()).toContain('Taramayı Başlat')
  })

  it('emits scan event on form submit with target, depth, and sensitivity values', async () => {
    const wrapper = mount(ScanForm, globalStubs)

    await wrapper.find('input').setValue('example.com')
    await wrapper.find('form').trigger('submit')

    const emitted = wrapper.emitted('scan')
    expect(emitted).toBeTruthy()
    expect(emitted).toHaveLength(1)
    expect(emitted![0]).toEqual(['example.com', 'standard', 'safe'])
  })

  it('submit button is disabled when scanning prop is true', () => {
    const wrapper = mount(ScanForm, {
      props: { scanning: true },
      ...globalStubs,
    })

    const submitButton = wrapper.find('button[type="submit"]')
    expect(submitButton.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('Taranıyor...')
  })

  it('does NOT emit when target is empty', async () => {
    const wrapper = mount(ScanForm, globalStubs)

    await wrapper.find('form').trigger('submit')

    expect(wrapper.emitted('scan')).toBeFalsy()
  })

  it('renders depth selection buttons (Hızlı, Standart, Derin)', () => {
    const wrapper = mount(ScanForm, globalStubs)

    const text = wrapper.text()
    expect(text).toContain('Hızlı')
    expect(text).toContain('Standart')
    expect(text).toContain('Derin')
  })

  it('changes depth when depth button is clicked', async () => {
    const wrapper = mount(ScanForm, globalStubs)

    // Find the depth buttons - they are type="button" inside the depth section
    const allButtons = wrapper.findAll('button[type="button"]')
    // First 3 buttons are depth selectors (Hızlı, Standart, Derin)
    const quickButton = allButtons.find((btn) => btn.text().includes('Hızlı'))
    expect(quickButton).toBeTruthy()

    await quickButton!.trigger('click')

    // Fill in target and submit to verify the depth was changed
    await wrapper.find('input').setValue('test.com')
    await wrapper.find('form').trigger('submit')

    const emitted = wrapper.emitted('scan')
    expect(emitted).toBeTruthy()
    expect(emitted![0]).toEqual(['test.com', 'quick', 'safe'])
  })
})
