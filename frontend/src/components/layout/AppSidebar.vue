<script setup lang="ts">
import { useRoute } from 'vue-router'
import {
  ShieldCheck as ShieldIcon,
  LayoutDashboard,
  Server,
  Network,
  ShieldCheck,
  TrendingUp,
  Bug,
  AlertTriangle,
  Lock,
  Shield,
  ShieldAlert,
  Radio,
  CreditCard,
  Wrench,
  Bell,
  Settings,
  Users,
  Home,
  Flame,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-vue-next'

defineProps<{
  collapsed: boolean
}>()

defineEmits<{
  toggle: []
}>()

const route = useRoute()

interface NavItem {
  name: string
  label: string
  icon: typeof LayoutDashboard
  path: string
}

interface NavSection {
  title: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    title: '',
    items: [
      { name: 'dashboard', label: 'Genel Bakış', icon: LayoutDashboard, path: '/' },
      { name: 'assets', label: 'Cihazlar', icon: Server, path: '/assets' },
    ],
  },
  {
    title: 'Güvenlik',
    items: [
      { name: 'shield', label: 'Kalkan', icon: Shield, path: '/shield' },
      { name: 'shield-findings', label: 'Bulgular', icon: ShieldAlert, path: '/shield-findings' },
      { name: 'firewall', label: 'Güvenlik Duvarı', icon: Flame, path: '/firewall' },
      { name: 'vulnerabilities', label: 'Açıklar', icon: Bug, path: '/vulnerabilities' },
      { name: 'risk', label: 'Risk', icon: AlertTriangle, path: '/risk' },
    ],
  },
  {
    title: 'Ağ',
    items: [
      { name: 'topology', label: 'Ağ Haritası', icon: Network, path: '/topology' },
      { name: 'analytics', label: 'Analitik', icon: TrendingUp, path: '/analytics' },
      { name: 'compliance', label: 'Uyumluluk', icon: ShieldCheck, path: '/compliance' },
      { name: 'certificates', label: 'Sertifikalar', icon: Lock, path: '/certificates' },
    ],
  },
  {
    title: 'Topluluk',
    items: [
      { name: 'collective', label: 'Topluluk', icon: Users, path: '/collective' },
      { name: 'family', label: 'Aile', icon: Home, path: '/family' },
      { name: 'notifications', label: 'Bildirimler', icon: Bell, path: '/notifications' },
    ],
  },
  {
    title: 'Yönetim',
    items: [
      { name: 'remediation', label: 'Onarım', icon: Wrench, path: '/remediation' },
      { name: 'agents', label: 'Ajanlar', icon: Radio, path: '/agents' },
      { name: 'pricing', label: 'Fiyatlandırma', icon: CreditCard, path: '/pricing' },
      { name: 'settings', label: 'Ayarlar', icon: Settings, path: '/settings' },
    ],
  },
]

const isActive = (item: NavItem) => {
  if (item.path === '/') return route.path === '/'
  // Exact match first, then prefix match with boundary check
  // This prevents /shield matching /shield-findings
  if (route.path === item.path) return true
  return route.path.startsWith(item.path + '/')
}
</script>

<template>
  <aside
    class="glass-panel flex flex-col border-r border-[var(--border-glass)] transition-all duration-300"
    :class="collapsed ? 'w-16' : 'w-60'"
  >
    <!-- Logo / Title -->
    <div class="flex items-center gap-3 px-4 py-5 border-b border-[var(--border-glass)]">
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-500/20">
        <ShieldIcon class="h-5 w-5 text-cyan-400" />
      </div>
      <Transition name="fade">
        <div v-if="!collapsed" class="overflow-hidden whitespace-nowrap">
          <h1 class="text-sm font-bold tracking-wide text-neon-cyan">BIGR</h1>
          <p class="text-[10px] text-slate-500 leading-tight">Discovery</p>
        </div>
      </Transition>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 overflow-y-auto px-2 py-3 space-y-0.5">
      <template v-for="(section, si) in navSections" :key="si">
        <!-- Section separator + title -->
        <div v-if="section.title" class="mt-4 mb-1.5 first:mt-0">
          <div class="border-t border-[var(--border-glass)] mb-2" />
          <Transition name="fade">
            <span
              v-if="!collapsed"
              class="px-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500"
            >
              {{ section.title }}
            </span>
          </Transition>
        </div>

        <RouterLink
          v-for="item in section.items"
          :key="item.name"
          :to="item.path"
          class="group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all duration-200"
          :class="[
            isActive(item)
              ? 'bg-cyan-500/10 text-cyan-400'
              : 'text-slate-400 hover:bg-white/5 hover:text-slate-200',
          ]"
        >
          <!-- Active indicator -->
          <div
            v-if="isActive(item)"
            class="absolute left-0 top-1/2 h-6 w-0.5 -translate-y-1/2 rounded-r bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.6)]"
          />

          <component
            :is="item.icon"
            class="h-5 w-5 shrink-0 transition-colors"
            :class="isActive(item) ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'"
          />

          <Transition name="fade">
            <span v-if="!collapsed" class="truncate">{{ item.label }}</span>
          </Transition>

          <!-- Tooltip when collapsed -->
          <div
            v-if="collapsed"
            class="pointer-events-none absolute left-full ml-2 rounded-md bg-slate-800 px-2 py-1 text-xs text-slate-200 opacity-0 shadow-lg transition-opacity group-hover:opacity-100"
          >
            {{ item.label }}
          </div>
        </RouterLink>
      </template>
    </nav>

    <!-- Collapse Toggle -->
    <div class="border-t border-[var(--border-glass)] px-2 py-3">
      <button
        class="flex w-full items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs text-slate-500 transition-colors hover:bg-white/5 hover:text-slate-300"
        @click="$emit('toggle')"
      >
        <component :is="collapsed ? ChevronsRight : ChevronsLeft" class="h-4 w-4" />
        <span v-if="!collapsed" class="truncate">Daralt</span>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
