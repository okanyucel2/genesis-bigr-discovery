<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import AppSidebar from './AppSidebar.vue'
import AppHeader from './AppHeader.vue'

const route = useRoute()
const sidebarCollapsed = ref(false)

const hideLayout = computed(() => route.meta.hideLayout === true)
</script>

<template>
  <!-- Full-screen mode (onboarding etc.) -->
  <RouterView v-if="hideLayout" />

  <!-- Normal layout with sidebar + header -->
  <div v-else class="flex h-screen overflow-hidden bg-[var(--bg-space-deep)]">
    <AppSidebar :collapsed="sidebarCollapsed" @toggle="sidebarCollapsed = !sidebarCollapsed" />
    <div class="flex flex-1 flex-col overflow-hidden">
      <AppHeader />
      <main class="flex-1 overflow-y-auto p-6">
        <RouterView />
      </main>
    </div>
  </div>
</template>
