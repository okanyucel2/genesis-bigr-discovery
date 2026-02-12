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
      label: 'Açık Portlar',
      value: asset.value.open_ports.length,
      icon: Wifi,
      color: 'text-cyan-400',
    },
    {
      label: 'Güven',
      value: `${asset.value.confidence_score > 0 && asset.value.confidence_score <= 1 ? Math.round(asset.value.confidence_score * 10000) / 100 : Math.round(asset.value.confidence_score * 100) / 100}%`,
      icon: Shield,
      color: 'text-emerald-400',
    },
    {
      label: 'Tarama Geçmişi',
      value: history.value.length,
      icon: History,
      color: 'text-purple-400',
    },
    {
      label: 'Son Görülme',
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

  if (diffMins < 1) return 'az önce'
  if (diffMins < 60) return `${diffMins}dk önce`
  if (diffHours < 24) return `${diffHours}sa önce`
  if (diffDays < 7) return `${diffDays}g önce`
  return date.toLocaleDateString('tr-TR', { month: 'short', day: 'numeric' })
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
        Cihazlara Dön
      </Button>
    </div>

    <!-- Loading State -->
    <LoadingState
      v-if="loading && !asset"
      message="Cihaz detayları yükleniyor..."
    />

    <!-- Error State -->
    <div
      v-else-if="error && !asset"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">
        Cihaz Yüklenemedi
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
          Geri Dön
        </Button>
        <button
          class="rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          @click="fetchDetail(route.params.ip as string)"
        >
          Tekrar Dene
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
            Genel Bakış
          </TabsTrigger>
          <TabsTrigger
            value="history"
            class="gap-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400"
          >
            <History :size="14" />
            Geçmiş
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
            Portlar
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
              Açık Portlar
            </h3>
            <AssetPorts :ports="asset.open_ports" />
          </div>

          <!-- History Preview -->
          <div
            v-if="history.length > 0"
            class="glass-panel rounded-xl p-5"
          >
            <h3 class="mb-3 text-sm font-medium text-slate-300">
              Son Tarama Geçmişi
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
