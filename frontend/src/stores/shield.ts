import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { ShieldScan } from '@/types/shield'

export const useShieldStore = defineStore('shield', () => {
  const recentScans = ref<ShieldScan[]>([])
  const currentScanId = ref<string | null>(null)

  const currentScan = computed(() =>
    recentScans.value.find((s) => s.id === currentScanId.value) ?? null,
  )

  function addScan(scan: ShieldScan) {
    // Add to front, keep max 50 recent scans
    recentScans.value = [scan, ...recentScans.value.filter((s) => s.id !== scan.id)].slice(0, 50)
    currentScanId.value = scan.id
  }

  function updateScan(scan: ShieldScan) {
    const idx = recentScans.value.findIndex((s) => s.id === scan.id)
    if (idx !== -1) {
      recentScans.value[idx] = scan
    } else {
      addScan(scan)
    }
  }

  function $reset() {
    recentScans.value = []
    currentScanId.value = null
  }

  return {
    recentScans,
    currentScanId,
    currentScan,
    addScan,
    updateScan,
    $reset,
  }
})
