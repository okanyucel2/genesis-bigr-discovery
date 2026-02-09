<script setup lang="ts">
import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import type { TrendSeries } from '@/types/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
)

const props = withDefaults(
  defineProps<{
    series: TrendSeries | TrendSeries[]
    title: string
    multiline?: boolean
  }>(),
  {
    multiline: false,
  },
)

const seriesColors = [
  { border: '#22d3ee', bg: 'rgba(34, 211, 238, 0.15)' },
  { border: '#3b82f6', bg: 'rgba(59, 130, 246, 0.15)' },
  { border: '#8b5cf6', bg: 'rgba(139, 92, 246, 0.15)' },
  { border: '#10b981', bg: 'rgba(16, 185, 129, 0.15)' },
  { border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  { border: '#6b7280', bg: 'rgba(107, 114, 128, 0.15)' },
]

const allSeries = computed<TrendSeries[]>(() => {
  if (Array.isArray(props.series)) return props.series
  return [props.series]
})

const chartData = computed(() => {
  const first = allSeries.value[0]
  if (!first) return { labels: [], datasets: [] }

  const labels = first.points.map((p) => {
    const d = new Date(p.date)
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  })

  const datasets = allSeries.value.map((s, idx) => {
    const color = seriesColors[idx % seriesColors.length]!
    return {
      label: s.name,
      data: s.points.map((p) => p.value),
      borderColor: color.border,
      backgroundColor: props.multiline ? color.bg : color.bg,
      fill: props.multiline,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 5,
      borderWidth: 2,
    }
  })

  return { labels, datasets }
})

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  interaction: {
    mode: 'index' as const,
    intersect: false,
  },
  plugins: {
    legend: {
      display: allSeries.value.length > 1,
      position: 'bottom' as const,
      labels: {
        color: '#94a3b8',
        padding: 12,
        font: { size: 11 },
        usePointStyle: true,
        pointStyleWidth: 8,
      },
    },
    tooltip: {
      backgroundColor: 'rgba(15, 23, 42, 0.9)',
      titleColor: '#e2e8f0',
      bodyColor: '#94a3b8',
      borderColor: 'rgba(255, 255, 255, 0.1)',
      borderWidth: 1,
      padding: 10,
      cornerRadius: 8,
    },
  },
  scales: {
    x: {
      grid: { color: 'rgba(255, 255, 255, 0.05)' },
      ticks: { color: '#64748b', font: { size: 10 } },
    },
    y: {
      grid: { color: 'rgba(255, 255, 255, 0.05)' },
      ticks: { color: '#64748b', font: { size: 10 } },
      beginAtZero: true,
    },
  },
}))
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle class="text-base">{{ title }}</CardTitle>
    </CardHeader>
    <CardContent>
      <div class="h-64">
        <Line :data="chartData" :options="chartOptions" />
      </div>
    </CardContent>
  </Card>
</template>
