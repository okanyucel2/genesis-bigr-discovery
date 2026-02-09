<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import {
  Loader2,
  AlertTriangle,
  RefreshCw,
  X,
  Network,
  ChevronDown,
} from 'lucide-vue-next'
import { useTopology } from '@/composables/useTopology'
import { useSubnets } from '@/composables/useSubnets'
import type { TopologyNode } from '@/types/api'
import TopologyCanvas from '@/components/topology/TopologyCanvas.vue'
import TopologyLegend from '@/components/topology/TopologyLegend.vue'
import TopologyStats from '@/components/topology/TopologyStats.vue'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import IpLink from '@/components/shared/IpLink.vue'

const { nodes, edges, stats, loading, error, fetchTopology } = useTopology()
const { subnets, fetchSubnets } = useSubnets()

const selectedSubnet = ref<string>('')
const selectedNode = ref<TopologyNode | null>(null)
const sidebarOpen = ref(false)

function onNodeClick(node: TopologyNode) {
  selectedNode.value = node
  sidebarOpen.value = true
}

function closeSidebar() {
  sidebarOpen.value = false
  // Delay clearing node data for slide-out animation
  setTimeout(() => {
    if (!sidebarOpen.value) {
      selectedNode.value = null
    }
  }, 300)
}

function onSubnetChange() {
  closeSidebar()
  fetchTopology(selectedSubnet.value || undefined)
}

function refresh() {
  closeSidebar()
  fetchTopology(selectedSubnet.value || undefined)
}

onMounted(() => {
  fetchTopology()
  fetchSubnets()
})

watch(selectedSubnet, () => {
  onSubnetChange()
})
</script>

<template>
  <div class="flex h-full flex-col gap-4">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-2xl font-bold text-white">Network Topology</h1>
        <p class="mt-1 text-sm text-slate-400">
          Force-directed graph of discovered network assets
        </p>
      </div>
      <div class="flex items-center gap-3">
        <!-- Subnet Filter -->
        <div class="relative">
          <select
            v-model="selectedSubnet"
            class="appearance-none rounded-lg border border-white/10 bg-white/5 py-2 pl-3 pr-8 text-xs text-slate-300 backdrop-blur-sm transition-colors hover:bg-white/10 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/30"
          >
            <option value="">All Subnets</option>
            <option
              v-for="subnet in subnets"
              :key="subnet.id"
              :value="subnet.cidr"
            >
              {{ subnet.cidr }}{{ subnet.label ? ` (${subnet.label})` : '' }}
            </option>
          </select>
          <ChevronDown
            :size="14"
            class="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-slate-500"
          />
        </div>

        <!-- Refresh Button -->
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="refresh"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && nodes.length === 0"
      class="flex flex-1 flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Loading topology data...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && nodes.length === 0"
      class="glass-card mx-auto flex max-w-md flex-col items-center rounded-xl p-8 text-center"
    >
      <AlertTriangle class="h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">
        Unable to Load Topology
      </h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="refresh"
      >
        Try Again
      </button>
    </div>

    <!-- Topology Content -->
    <template v-else>
      <!-- Stats Bar -->
      <TopologyStats :stats="stats" />

      <!-- Canvas + Sidebar -->
      <div class="relative flex min-h-[600px] flex-1 overflow-hidden rounded-xl border border-white/5 bg-white/[0.02]">
        <!-- Canvas fills remaining space -->
        <div class="flex-1">
          <TopologyCanvas
            :nodes="nodes"
            :edges="edges"
            @node-click="onNodeClick"
          />
        </div>

        <!-- Sidebar Panel (slides in from right) -->
        <div
          class="absolute right-0 top-0 h-full w-80 transform border-l border-white/10 bg-slate-950/95 backdrop-blur-lg transition-transform duration-300"
          :class="sidebarOpen ? 'translate-x-0' : 'translate-x-full'"
        >
          <div v-if="selectedNode" class="flex h-full flex-col">
            <!-- Sidebar Header -->
            <div class="flex items-center justify-between border-b border-white/10 px-4 py-3">
              <div class="flex items-center gap-2">
                <Network :size="16" class="text-cyan-400" />
                <h3 class="text-sm font-semibold text-white">Node Details</h3>
              </div>
              <button
                class="rounded-md p-1 text-slate-400 transition-colors hover:bg-white/10 hover:text-white"
                @click="closeSidebar"
              >
                <X :size="16" />
              </button>
            </div>

            <!-- Sidebar Content -->
            <div class="flex-1 space-y-4 overflow-y-auto p-4">
              <!-- Identity -->
              <div class="space-y-2">
                <h4 class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                  Identity
                </h4>
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Label</span>
                    <span class="text-xs font-medium text-white">{{ selectedNode.label }}</span>
                  </div>
                  <div v-if="selectedNode.ip" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">IP</span>
                    <IpLink :ip="selectedNode.ip" />
                  </div>
                  <div v-if="selectedNode.mac" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">MAC</span>
                    <span class="font-mono text-xs text-slate-300">{{ selectedNode.mac }}</span>
                  </div>
                  <div v-if="selectedNode.hostname" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Hostname</span>
                    <span class="text-xs text-white">{{ selectedNode.hostname }}</span>
                  </div>
                  <div v-if="selectedNode.vendor" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Vendor</span>
                    <span class="text-xs text-white">{{ selectedNode.vendor }}</span>
                  </div>
                </div>
              </div>

              <!-- Classification -->
              <div class="space-y-2">
                <h4 class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                  Classification
                </h4>
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Type</span>
                    <span
                      class="rounded-full px-2 py-0.5 text-[10px] font-medium"
                      :style="{
                        backgroundColor: selectedNode.color + '20',
                        color: selectedNode.color,
                      }"
                    >
                      {{ selectedNode.type }}
                    </span>
                  </div>
                  <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Category</span>
                    <BigrBadge :category="selectedNode.bigr_category" />
                  </div>
                  <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Confidence</span>
                    <span class="text-xs tabular-nums text-white">
                      {{ Math.round(selectedNode.confidence * 100) }}%
                    </span>
                  </div>
                </div>
              </div>

              <!-- Network -->
              <div class="space-y-2">
                <h4 class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                  Network
                </h4>
                <div class="space-y-1.5">
                  <div v-if="selectedNode.subnet" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Subnet</span>
                    <span class="font-mono text-xs text-slate-300">{{ selectedNode.subnet }}</span>
                  </div>
                  <div v-if="selectedNode.switch_port" class="flex items-center justify-between">
                    <span class="text-xs text-slate-500">Switch Port</span>
                    <span class="font-mono text-xs text-slate-300">{{ selectedNode.switch_port }}</span>
                  </div>
                </div>
              </div>

              <!-- Open Ports -->
              <div v-if="selectedNode.open_ports.length > 0" class="space-y-2">
                <h4 class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                  Open Ports
                </h4>
                <div class="flex flex-wrap gap-1.5">
                  <span
                    v-for="port in selectedNode.open_ports"
                    :key="port"
                    class="rounded-md bg-white/5 px-2 py-0.5 font-mono text-[11px] text-slate-300"
                  >
                    {{ port }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Legend -->
      <TopologyLegend />
    </template>
  </div>
</template>
