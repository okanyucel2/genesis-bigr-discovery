<script setup lang="ts">
import { onMounted, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAssetDetail } from '@/composables/useAssetDetail'
import AssetDetailCard from '@/components/assets/AssetDetailCard.vue'
import AssetHistory from '@/components/assets/AssetHistory.vue'
import AssetPorts from '@/components/assets/AssetPorts.vue'
import LoadingState from '@/components/shared/LoadingState.vue'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import {
  ArrowLeft,
  AlertTriangle,
  Monitor,
  History,
  Network,
  Shield,
  Clock,
  Wifi,
} from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const { asset, history, loading, error, fetchDetail } = useAssetDetail()

onMounted(() => {
  const ip = route.params.ip as string
  if (ip) fetchDetail(ip)
})

watch(
  () => route.params.ip,
  (newIp) => {
    if (newIp) fetchDetail(newIp as string)
  },
)

function goBack() {
  router.push('/assets')
}

// Quick stats for the overview tab
const quickStats = computed(() => {
  if (!asset.value) return []
  return [
    {
      label: 'Open Ports',
      value: asset.value.open_ports.length,
      icon: Wifi,
      color: 'text-cyan-400',
    },
    {
      label: 'Confidence',
      value: `${asset.value.confidence_score}%`,
      icon: Shield,
      color: 'text-emerald-400',
    },
    {
      label: 'Scan History',
      value: history.value.length,
      icon: History,
      color: 'text-purple-400',
    },
    {
      label: 'Last Seen',
      value: asset.value.last_seen
        ? formatRelativeTime(asset.value.last_seen)
        : 'N/A',
      icon: Clock,
      color: 'text-amber-400',
    },
  ]
})

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}
</script>

<template>
  <div class="space-y-6">
    <!-- Back Navigation -->
    <div>
      <Button
        variant="ghost"
        size="sm"
        class="gap-2 text-slate-400 hover:text-slate-200"
        @click="goBack"
      >
        <ArrowLeft :size="16" />
        Back to Assets
      </Button>
    </div>

    <!-- Loading State -->
    <LoadingState
      v-if="loading && !asset"
      message="Loading asset details..."
    />

    <!-- Error State -->
    <div
      v-else-if="error && !asset"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">
        Unable to Load Asset
      </h2>
      <p class="mt-2 text-sm text-slate-400">
        {{ error }}
      </p>
      <div class="mt-4 flex justify-center gap-3">
        <Button
          variant="ghost"
          size="sm"
          class="text-slate-400"
          @click="goBack"
        >
          Go Back
        </Button>
        <button
          class="rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          @click="fetchDetail(route.params.ip as string)"
        >
          Try Again
        </button>
      </div>
    </div>

    <!-- Asset Detail Content -->
    <template v-if="asset">
      <!-- Main Detail Card -->
      <AssetDetailCard :asset="asset" />

      <!-- Tabs Section -->
      <Tabs default-value="overview" class="w-full">
        <TabsList class="w-full justify-start bg-white/[0.04] border border-white/[0.06]">
          <TabsTrigger
            value="overview"
            class="gap-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400"
          >
            <Monitor :size="14" />
            Overview
          </TabsTrigger>
          <TabsTrigger
            value="history"
            class="gap-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400"
          >
            <History :size="14" />
            History
            <span
              v-if="history.length > 0"
              class="ml-1 rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] font-semibold"
            >
              {{ history.length }}
            </span>
          </TabsTrigger>
          <TabsTrigger
            value="ports"
            class="gap-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400"
          >
            <Network :size="14" />
            Ports
            <span
              v-if="asset.open_ports.length > 0"
              class="ml-1 rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] font-semibold"
            >
              {{ asset.open_ports.length }}
            </span>
          </TabsTrigger>
        </TabsList>

        <!-- Overview Tab -->
        <TabsContent value="overview" class="mt-4 space-y-6">
          <!-- Quick Stats -->
          <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div
              v-for="stat in quickStats"
              :key="stat.label"
              class="glass-panel rounded-xl p-4"
            >
              <div class="flex items-center gap-2">
                <component
                  :is="stat.icon"
                  :size="16"
                  :class="stat.color"
                />
                <span class="text-xs text-slate-500">{{ stat.label }}</span>
              </div>
              <p class="mt-2 text-xl font-bold text-slate-200 tabular-nums">
                {{ stat.value }}
              </p>
            </div>
          </div>

          <!-- Ports Preview -->
          <div class="glass-panel rounded-xl p-5">
            <h3 class="mb-3 text-sm font-medium text-slate-300">
              Open Ports
            </h3>
            <AssetPorts :ports="asset.open_ports" />
          </div>

          <!-- History Preview -->
          <div
            v-if="history.length > 0"
            class="glass-panel rounded-xl p-5"
          >
            <h3 class="mb-3 text-sm font-medium text-slate-300">
              Recent Scan History
            </h3>
            <AssetHistory :history="history.slice(0, 5)" />
          </div>
        </TabsContent>

        <!-- History Tab -->
        <TabsContent value="history" class="mt-4">
          <AssetHistory :history="history" />
        </TabsContent>

        <!-- Ports Tab -->
        <TabsContent value="ports" class="mt-4">
          <div class="glass-panel rounded-xl p-5">
            <AssetPorts :ports="asset.open_ports" />
          </div>
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>
