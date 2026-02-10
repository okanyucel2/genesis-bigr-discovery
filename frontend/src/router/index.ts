import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: () => import('@/views/DashboardView.vue'),
    },
    {
      path: '/onboarding',
      name: 'onboarding',
      component: () => import('@/views/OnboardingView.vue'),
      meta: { hideLayout: true },
    },
    {
      path: '/assets',
      name: 'assets',
      component: () => import('@/views/AssetsView.vue'),
    },
    {
      path: '/assets/:ip',
      name: 'asset-detail',
      component: () => import('@/views/AssetDetailView.vue'),
    },
    {
      path: '/topology',
      name: 'topology',
      component: () => import('@/views/TopologyView.vue'),
    },
    {
      path: '/compliance',
      name: 'compliance',
      component: () => import('@/views/ComplianceView.vue'),
    },
    {
      path: '/analytics',
      name: 'analytics',
      component: () => import('@/views/AnalyticsView.vue'),
    },
    {
      path: '/vulnerabilities',
      name: 'vulnerabilities',
      component: () => import('@/views/VulnerabilitiesView.vue'),
    },
    {
      path: '/risk',
      name: 'risk',
      component: () => import('@/views/RiskView.vue'),
    },
    {
      path: '/certificates',
      name: 'certificates',
      component: () => import('@/views/CertificatesView.vue'),
    },
    {
      path: '/shield',
      name: 'shield',
      component: () => import('@/views/ShieldView.vue'),
    },
    {
      path: '/shield/scan/:id',
      name: 'shield-scan',
      component: () => import('@/views/ShieldView.vue'),
    },
    {
      path: '/shield-findings',
      name: 'shield-findings',
      component: () => import('@/views/ShieldFindingsView.vue'),
    },
    {
      path: '/notifications',
      name: 'notifications',
      component: () => import('@/views/NotificationsView.vue'),
    },
    {
      path: '/remediation',
      name: 'remediation',
      component: () => import('@/views/RemediationView.vue'),
    },
    {
      path: '/firewall',
      name: 'firewall',
      component: () => import('@/views/FirewallView.vue'),
    },
    {
      path: '/collective',
      name: 'collective',
      component: () => import('@/views/CollectiveView.vue'),
    },
    {
      path: '/family',
      name: 'family',
      component: () => import('@/views/FamilyView.vue'),
    },
    {
      path: '/agents',
      name: 'agents',
      component: () => import('@/views/AgentsView.vue'),
    },
    {
      path: '/pricing',
      name: 'pricing',
      component: () => import('@/views/PricingView.vue'),
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/SettingsView.vue'),
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      component: () => import('@/views/NotFoundView.vue'),
    },
  ],
})

export default router
