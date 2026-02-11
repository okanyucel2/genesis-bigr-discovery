<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import AppSidebar from './AppSidebar.vue'
import AppHeader from './AppHeader.vue'
import MobileTabBar from './MobileTabBar.vue'

const route = useRoute()
const sidebarCollapsed = ref(false)

const hideLayout = computed(() => route.meta.hideLayout === true)
</script>

<template>
  <!-- Full-screen mode (onboarding etc.) -->
  <RouterView v-if="hideLayout" />

  <!-- Normal layout with sidebar + header + mobile tab bar -->
  <div v-else class="flex h-screen overflow-hidden bg-[var(--bg-space-deep)]">
    <!-- Sidebar: hidden on mobile -->
    <AppSidebar
      class="hidden md:flex"
      :collapsed="sidebarCollapsed"
      @toggle="sidebarCollapsed = !sidebarCollapsed"
    />
    <div class="flex flex-1 flex-col overflow-hidden">
      <AppHeader />
      <main class="flex-1 overflow-y-auto p-4 pb-20 md:p-6 md:pb-6">
        <RouterView />
      </main>
    </div>
    <!-- Mobile tab bar -->
    <MobileTabBar />
  </div>
</template>
