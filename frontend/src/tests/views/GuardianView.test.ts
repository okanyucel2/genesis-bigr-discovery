import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GuardianView from '@/views/GuardianView.vue'

vi.mock('@/composables/useGuardian', () => ({
  useGuardian: vi.fn(() => ({
    status: { value: null },
    stats: { value: null },
    rules: { value: [] },
    blocklists: { value: [] },
    health: { value: null },
    loading: { value: false },
    error: { value: null },
    blockRules: { value: [] },
    allowRules: { value: [] },
    activeBlocklists: { value: [] },
    fetchStatus: vi.fn(),
    fetchStats: vi.fn(),
    fetchRules: vi.fn(),
    fetchBlocklists: vi.fn(),
    fetchHealth: vi.fn(),
    addRule: vi.fn(),
    deleteRule: vi.fn(),
    updateBlocklists: vi.fn(),
    refreshAll: vi.fn(),
  })),
}))

import { useGuardian } from '@/composables/useGuardian'
import { ref, computed } from 'vue'

describe('GuardianView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows loading state when loading with no status', () => {
    vi.mocked(useGuardian).mockReturnValue({
      status: ref(null),
      stats: ref(null),
      rules: ref([]),
      blocklists: ref([]),
      health: ref(null),
      loading: ref(true),
      error: ref(null),
      blockRules: computed(() => []),
      allowRules: computed(() => []),
      activeBlocklists: computed(() => []),
      fetchStatus: vi.fn(),
      fetchStats: vi.fn(),
      fetchRules: vi.fn(),
      fetchBlocklists: vi.fn(),
      fetchHealth: vi.fn(),
      addRule: vi.fn(),
      deleteRule: vi.fn(),
      updateBlocklists: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(GuardianView)
    expect(wrapper.text()).toContain('Guardian durumu yukleniyor')
  })

  it('shows active status banner when guardian is active', async () => {
    vi.mocked(useGuardian).mockReturnValue({
      status: ref({
        guardian_active: true,
        dns_filtering: true,
        blocked_domains_count: 45000,
        stats: { total_queries: 1000, blocked_queries: 100, allowed_queries: 900, cache_hit_rate: 0.4 },
        lifetime_stats: { total_queries: 5000, blocked_queries: 500, allowed_queries: 4500 },
      }),
      stats: ref(null),
      rules: ref([]),
      blocklists: ref([]),
      health: ref(null),
      loading: ref(false),
      error: ref(null),
      blockRules: computed(() => []),
      allowRules: computed(() => []),
      activeBlocklists: computed(() => []),
      fetchStatus: vi.fn(),
      fetchStats: vi.fn(),
      fetchRules: vi.fn(),
      fetchBlocklists: vi.fn(),
      fetchHealth: vi.fn(),
      addRule: vi.fn(),
      deleteRule: vi.fn(),
      updateBlocklists: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(GuardianView)
    expect(wrapper.text()).toContain('Guardian Aktif')
    expect(wrapper.text()).toContain('45,000')
  })

  it('shows inactive status banner when guardian is offline', async () => {
    vi.mocked(useGuardian).mockReturnValue({
      status: ref({
        guardian_active: false,
        dns_filtering: false,
        blocked_domains_count: 0,
        stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0, cache_hit_rate: 0 },
        lifetime_stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0 },
      }),
      stats: ref(null),
      rules: ref([]),
      blocklists: ref([]),
      health: ref(null),
      loading: ref(false),
      error: ref(null),
      blockRules: computed(() => []),
      allowRules: computed(() => []),
      activeBlocklists: computed(() => []),
      fetchStatus: vi.fn(),
      fetchStats: vi.fn(),
      fetchRules: vi.fn(),
      fetchBlocklists: vi.fn(),
      fetchHealth: vi.fn(),
      addRule: vi.fn(),
      deleteRule: vi.fn(),
      updateBlocklists: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(GuardianView)
    expect(wrapper.text()).toContain('Guardian Cevrimdisi')
  })

  it('renders stats cards with correct values', () => {
    vi.mocked(useGuardian).mockReturnValue({
      status: ref({
        guardian_active: true,
        dns_filtering: true,
        blocked_domains_count: 45000,
        stats: { total_queries: 1847, blocked_queries: 156, allowed_queries: 1691, cache_hit_rate: 0.42 },
        lifetime_stats: { total_queries: 23456, blocked_queries: 2341, allowed_queries: 21115 },
      }),
      stats: ref(null),
      rules: ref([]),
      blocklists: ref([]),
      health: ref(null),
      loading: ref(false),
      error: ref(null),
      blockRules: computed(() => []),
      allowRules: computed(() => []),
      activeBlocklists: computed(() => []),
      fetchStatus: vi.fn(),
      fetchStats: vi.fn(),
      fetchRules: vi.fn(),
      fetchBlocklists: vi.fn(),
      fetchHealth: vi.fn(),
      addRule: vi.fn(),
      deleteRule: vi.fn(),
      updateBlocklists: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(GuardianView)
    expect(wrapper.text()).toContain('1,847')
    expect(wrapper.text()).toContain('156')
    expect(wrapper.text()).toContain('42%')
  })

  it('calls refreshAll on mount', () => {
    const refreshAllFn = vi.fn()
    vi.mocked(useGuardian).mockReturnValue({
      status: ref(null),
      stats: ref(null),
      rules: ref([]),
      blocklists: ref([]),
      health: ref(null),
      loading: ref(false),
      error: ref(null),
      blockRules: computed(() => []),
      allowRules: computed(() => []),
      activeBlocklists: computed(() => []),
      fetchStatus: vi.fn(),
      fetchStats: vi.fn(),
      fetchRules: vi.fn(),
      fetchBlocklists: vi.fn(),
      fetchHealth: vi.fn(),
      addRule: vi.fn(),
      deleteRule: vi.fn(),
      updateBlocklists: vi.fn(),
      refreshAll: refreshAllFn,
    })

    mount(GuardianView)
    expect(refreshAllFn).toHaveBeenCalled()
  })
})
