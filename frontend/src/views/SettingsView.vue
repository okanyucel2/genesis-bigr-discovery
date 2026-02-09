<script setup lang="ts">
import { computed } from 'vue'
import {
  Settings,
  Globe,
  CheckCircle,
  XCircle,
  Radar,
  Info,
} from 'lucide-vue-next'
import { useHealth } from '@/composables/useHealth'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'

const { status, dataFile, dataExists } = useHealth()

const apiUrl = computed(() => {
  const envUrl = import.meta.env.VITE_API_URL
  return envUrl || `${window.location.origin}`
})

const statusColor = computed(() => {
  switch (status.value) {
    case 'ok':
      return 'text-emerald-400'
    case 'error':
      return 'text-rose-400'
    default:
      return 'text-amber-400'
  }
})

const statusLabel = computed(() => {
  switch (status.value) {
    case 'ok':
      return 'Connected'
    case 'error':
      return 'Disconnected'
    default:
      return 'Checking...'
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h1 class="text-2xl font-bold text-white">Settings</h1>
      <p class="mt-1 text-sm text-slate-400">
        Configuration and system information
      </p>
    </div>

    <!-- Tabs -->
    <Tabs default-value="general">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="scanner">Scanner</TabsTrigger>
        <TabsTrigger value="about">About</TabsTrigger>
      </TabsList>

      <!-- General Tab -->
      <TabsContent value="general">
        <div class="space-y-4">
          <!-- API Connection -->
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Globe :size="16" class="text-cyan-400" />
                API Connection
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Endpoint URL</span>
                  <span class="font-mono text-sm text-slate-300">{{ apiUrl }}</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Status</span>
                  <div class="flex items-center gap-2">
                    <component
                      :is="status === 'ok' ? CheckCircle : status === 'error' ? XCircle : Settings"
                      :size="14"
                      :class="statusColor"
                    />
                    <span class="text-sm font-medium" :class="statusColor">
                      {{ statusLabel }}
                    </span>
                  </div>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Data File</span>
                  <span class="font-mono text-xs text-slate-400">
                    {{ dataFile ?? 'N/A' }}
                  </span>
                </div>
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Data Available</span>
                  <div class="flex items-center gap-2">
                    <component
                      :is="dataExists ? CheckCircle : XCircle"
                      :size="14"
                      :class="dataExists ? 'text-emerald-400' : 'text-rose-400'"
                    />
                    <span
                      class="text-sm"
                      :class="dataExists ? 'text-emerald-400' : 'text-rose-400'"
                    >
                      {{ dataExists ? 'Yes' : 'No' }}
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <!-- Scanner Tab -->
      <TabsContent value="scanner">
        <div class="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Radar :size="16" class="text-cyan-400" />
                Scanner Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Scanner Type</span>
                  <span class="text-sm text-slate-300">Nmap + ARP Sweep</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Target Subnet</span>
                  <span class="font-mono text-sm text-slate-300">Configured via CLI</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Scan Methods</span>
                  <span class="text-sm text-slate-300">nmap, arp, passive</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Classification</span>
                  <span class="text-sm text-slate-300">BIGR 4-Category System</span>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Categories</p>
                  <div class="mt-2 grid grid-cols-2 gap-2">
                    <div class="rounded-lg bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
                      Network &amp; Systems
                    </div>
                    <div class="rounded-lg bg-purple-500/10 px-3 py-2 text-xs text-purple-400">
                      Applications
                    </div>
                    <div class="rounded-lg bg-emerald-500/10 px-3 py-2 text-xs text-emerald-400">
                      IoT Devices
                    </div>
                    <div class="rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
                      Portable Devices
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <!-- About Tab -->
      <TabsContent value="about">
        <div class="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Info :size="16" class="text-cyan-400" />
                About BIGR Discovery
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Version</span>
                  <span class="font-mono text-sm text-slate-300">0.1.0</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Project</span>
                  <span class="text-sm text-slate-300">GENESIS v3 - BIGR Discovery</span>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Description</p>
                  <p class="mt-1 text-sm leading-relaxed text-slate-300">
                    BIGR Discovery is an autonomous network asset discovery and classification agent.
                    It scans network subnets, identifies devices, classifies them according to the
                    BIGR 4-category system, tracks changes over time, and provides risk assessment
                    with CVE matching.
                  </p>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Tech Stack</p>
                  <div class="mt-2 flex flex-wrap gap-2">
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Python 3.12+</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">FastAPI</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Vue 3</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">TypeScript</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Tailwind CSS</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Chart.js</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Nmap</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Scapy</span>
                  </div>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Credits</p>
                  <p class="mt-1 text-sm text-slate-300">
                    Built as part of the GENESIS autonomous code quality platform.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>
    </Tabs>
  </div>
</template>
