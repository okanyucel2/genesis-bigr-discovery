<script setup lang="ts">
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  LineController,
  BarController,
} from 'chart.js'
import type { ChartData } from 'chart.js'
import type { ScanFrequency } from '@/types/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  LineController,
  BarController,
)

const props = defineProps<{
  data: ScanFrequency[]
}>()

const chartData = computed((): ChartData => {
  const labels = props.data.map((d) => {
    const date = new Date(d.date)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  })

  return {
    labels,
    datasets: [
      {
        type: 'bar' as const,
        label: 'Scans',
        data: props.data.map((d) => d.scan_count),
        backgroundColor: 'rgba(34, 211, 238, 0.3)',
        borderColor: '#22d3ee',
        borderWidth: 1,
        borderRadius: 4,
        yAxisID: 'y',
      },
      {
        type: 'line' as const,
        label: 'Total Assets',
        data: props.data.map((d) => d.total_assets),
        borderColor: '#a78bfa',
        backgroundColor: 'rgba(167, 139, 250, 0.1)',
        borderWidth: 2,
        tension: 0.3,
        pointRadius: 2,
        pointHoverRadius: 5,
        yAxisID: 'y1',
      },
    ],
  }
})

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  interaction: {
    mode: 'index' as const,
    intersect: false,
  },
  plugins: {
    legend: {
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
      position: 'left' as const,
      grid: { color: 'rgba(255, 255, 255, 0.05)' },
      ticks: { color: '#22d3ee', font: { size: 10 } },
      title: {
        display: true,
        text: 'Scans',
        color: '#22d3ee',
        font: { size: 11 },
      },
      beginAtZero: true,
    },
    y1: {
      position: 'right' as const,
      grid: { drawOnChartArea: false },
      ticks: { color: '#a78bfa', font: { size: 10 } },
      title: {
        display: true,
        text: 'Assets',
        color: '#a78bfa',
        font: { size: 11 },
      },
      beginAtZero: true,
    },
  },
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Scan Frequency</CardTitle>
    </CardHeader>
    <CardContent>
      <div class="h-64">
        <Bar :data="(chartData as any)" :options="chartOptions" />
      </div>
    </CardContent>
  </Card>
</template>
