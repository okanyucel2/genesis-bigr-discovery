<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAnalytics } from '@/composables/useAnalytics'
import { Button } from '@/components/ui/button'
import LoadingState from '@/components/shared/LoadingState.vue'
import EmptyState from '@/components/shared/EmptyState.vue'
import TrendLineChart from '@/components/analytics/TrendLineChart.vue'
import ScanFrequencyChart from '@/components/analytics/ScanFrequencyChart.vue'
import MostChangedTable from '@/components/analytics/MostChangedTable.vue'

const { data, loading, error, fetchAnalytics } = useAnalytics()

const selectedDays = ref(30)

const timeRanges = [
  { label: '7d', days: 7 },
  { label: '30d', days: 30 },
  { label: '90d', days: 90 },
]

function selectRange(days: number) {
  selectedDays.value = days
  fetchAnalytics(days)
}

onMounted(() => {
  fetchAnalytics(selectedDays.value)
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-bold text-white">Analytics & Trends</h1>

      <!-- Time range selector -->
      <div class="flex gap-1 rounded-lg border border-border bg-white/5 p-1">
        <Button
          v-for="range in timeRanges"
          :key="range.days"
          :variant="selectedDays === range.days ? 'default' : 'ghost'"
          size="sm"
          class="text-xs"
          @click="selectRange(range.days)"
        >
          {{ range.label }}
        </Button>
      </div>
    </div>

    <LoadingState v-if="loading" message="Loading analytics data..." />

    <div v-else-if="error" class="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4">
      <p class="text-sm text-rose-400">{{ error }}</p>
    </div>

    <EmptyState
      v-else-if="!data"
      title="No Analytics Data"
      description="Run scans over time to generate trend analytics."
    />

    <template v-else>
      <!-- Asset count trend (full width) -->
      <TrendLineChart
        v-if="data.asset_count_trend"
        :series="data.asset_count_trend"
        title="Asset Count Trend"
      />

      <!-- Category trends (stacked area, full width) -->
      <TrendLineChart
        v-if="data.category_trends.length > 0"
        :series="data.category_trends"
        title="Category Trends"
        :multiline="true"
      />

      <!-- Bottom row: Scan frequency + Most changed side by side -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ScanFrequencyChart
          v-if="data.scan_frequency.length > 0"
          :data="data.scan_frequency"
        />

        <MostChangedTable
          v-if="data.most_changed_assets.length > 0"
          :assets="data.most_changed_assets"
        />
      </div>
    </template>
  </div>
</template>
