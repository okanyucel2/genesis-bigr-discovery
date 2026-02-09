<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw, Loader2, AlertTriangle } from 'lucide-vue-next'
import { useCertificates } from '@/composables/useCertificates'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import SearchInput from '@/components/shared/SearchInput.vue'
import CertSummaryCards from '@/components/certificates/CertSummaryCards.vue'
import CertTable from '@/components/certificates/CertTable.vue'

const { data, loading, error, fetchCertificates } = useCertificates()

const search = ref('')
const activeFilter = ref('all')

onMounted(() => {
  fetchCertificates()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">TLS Certificates</h1>
        <p class="mt-1 text-sm text-slate-400">
          Certificate inventory and expiration tracking
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        :disabled="loading"
        @click="fetchCertificates"
      >
        <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
        Refresh
      </button>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !data"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Loading certificate data...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && !data"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Unable to Load Data</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="fetchCertificates"
      >
        Try Again
      </button>
    </div>

    <!-- Content -->
    <template v-else-if="data">
      <!-- Summary Cards -->
      <CertSummaryCards :certificates="data.certificates" />

      <!-- Search -->
      <SearchInput
        v-model="search"
        placeholder="Search by IP, CN, or issuer..."
        class="max-w-md"
      />

      <!-- Filter Tabs + Table -->
      <Tabs v-model="activeFilter" default-value="all">
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="expiring">Expiring Soon</TabsTrigger>
          <TabsTrigger value="expired">Expired</TabsTrigger>
          <TabsTrigger value="self-signed">Self-Signed</TabsTrigger>
        </TabsList>

        <TabsContent value="all">
          <CertTable :certificates="data.certificates" :search="search" filter="all" />
        </TabsContent>

        <TabsContent value="expiring">
          <CertTable :certificates="data.certificates" :search="search" filter="expiring" />
        </TabsContent>

        <TabsContent value="expired">
          <CertTable :certificates="data.certificates" :search="search" filter="expired" />
        </TabsContent>

        <TabsContent value="self-signed">
          <CertTable :certificates="data.certificates" :search="search" filter="self-signed" />
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>
