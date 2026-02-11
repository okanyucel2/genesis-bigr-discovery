<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { Shield, Users, Server, Settings } from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()

const tabs = [
  { name: 'home', label: 'Ana', icon: Shield, path: '/' },
  { name: 'family', label: 'Ailem', icon: Users, path: '/family' },
  { name: 'assets', label: 'Cihazlar', icon: Server, path: '/assets' },
  { name: 'settings', label: 'Ayarlar', icon: Settings, path: '/settings' },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function navigate(path: string) {
  router.push(path)
}
</script>

<template>
  <nav class="mobile-tab-bar fixed bottom-0 left-0 right-0 z-50 border-t border-[var(--border-glass)] bg-[var(--bg-glass-heavy)] backdrop-blur-xl md:hidden">
    <div class="flex h-16 items-center justify-around px-2">
      <button
        v-for="tab in tabs"
        :key="tab.name"
        class="flex flex-1 flex-col items-center gap-1 py-2 transition-colors"
        :class="isActive(tab.path) ? 'text-cyan-400' : 'text-slate-500'"
        @click="navigate(tab.path)"
      >
        <component
          :is="tab.icon"
          class="h-5 w-5"
          :class="isActive(tab.path) ? 'text-cyan-400' : 'text-slate-500'"
        />
        <span class="text-[10px] font-medium">{{ tab.label }}</span>
      </button>
    </div>
    <!-- Safe area for iOS -->
    <div class="h-[env(safe-area-inset-bottom)]" />
  </nav>
</template>
