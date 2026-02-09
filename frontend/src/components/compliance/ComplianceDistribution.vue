<script setup lang="ts">
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'
import type { ComplianceResponse } from '@/types/api'
import { BIGR_CATEGORIES, type BigrCategory } from '@/types/bigr'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps<{
  distribution: ComplianceResponse['distribution']
}>()

const categoryKeys: BigrCategory[] = [
  'ag_ve_sistemler',
  'uygulamalar',
  'iot',
  'tasinabilir',
  'unclassified',
]

const chartData = computed(() => ({
  labels: categoryKeys.map((k) => BIGR_CATEGORIES[k].label),
  datasets: [
    {
      data: categoryKeys.map((k) => props.distribution[k] || 0),
      backgroundColor: categoryKeys.map(
        (k) => BIGR_CATEGORIES[k].color + '80',
      ),
      borderColor: categoryKeys.map((k) => BIGR_CATEGORIES[k].color),
      borderWidth: 1,
      hoverBorderWidth: 2,
      hoverOffset: 6,
    },
  ],
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
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
      callbacks: {
        label: (context: { label?: string; parsed: number; dataset: { data: number[] } }) => {
          const total = context.dataset.data.reduce(
            (sum: number, val: number) => sum + val,
            0,
          )
          const percentage =
            total > 0 ? ((context.parsed / total) * 100).toFixed(1) : '0'
          return ` ${context.label}: ${context.parsed} (${percentage}%)`
        },
      },
    },
  },
  cutout: '65%',
  animation: {
    animateRotate: true,
    animateScale: true,
  },
}
</script>

<template>
  <div class="h-64">
    <Doughnut :data="chartData" :options="chartOptions" />
  </div>
</template>
